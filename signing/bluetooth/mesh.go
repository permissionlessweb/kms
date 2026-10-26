package bluetooth

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mesh: one sealed link per authorized phone.
//
// The scanner (scripts/ble-scan.swift) holds one CoreBluetooth connection
// per chosen pairing code and gives each its own request drop under
// <home>/links/<code>/ (req.json, resp.json, keys). Each Link runs its own
// Noise XX session, its own request lock and its own redial loop, so a vote
// for one slot never waits on another phone's radio. A vote for a slot goes
// only to the link whose session is with the phone pinned for that slot
// (peers/<slot>.peer, else the legacy global pin). A phone with no pin is
// stopped after message 2 of the handshake: it never holds a session and
// never sees a vote; its static waits in phone.pending for the operator to
// compare fingerprint tiles.
//
// With no <home>/links directory (old scanner) the mesh is the single root
// link, exactly the pre-mesh behaviour.

// MaxLinks caps concurrent phone links. Neither CoreBluetooth nor Android
// documents a hard limit; Apple controllers are practically good for ~8 LE
// links, and Android's GATT stack defaults to 7 concurrent connections.
const MaxLinks = 7

// Redial: first retry after redialBase, doubling to RedialMax, each with up
// to 30% jitter so links that drop together do not retry in lockstep.
var (
	redialBase = 150 * time.Millisecond
	RedialMax  = 750 * time.Millisecond
	// unpinnedRetry spaces handshakes with a phone that is not pinned: it is
	// asked only often enough to show its fingerprint for pairing.
	unpinnedRetry = 5 * time.Second
	meshTick      = 100 * time.Millisecond
)

// Mesh routes each slot's votes to the phone pinned for it.
type Mesh struct {
	home  string
	root  *Link
	mu    sync.Mutex
	links map[string]*Link
	stop  chan struct{}
	once  sync.Once
	rmu   sync.Mutex // redial schedule
}

var (
	meshOnce    sync.Once
	defaultMesh *Mesh
)

// DefaultMesh is the console's mesh at Dir; its root link is DefaultLink.
func DefaultMesh() *Mesh {
	meshOnce.Do(func() {
		defaultMesh = &Mesh{home: Dir, root: DefaultLink(), links: map[string]*Link{}}
		defaultMesh.Start()
	})
	return defaultMesh
}

// NewMesh is a mesh rooted at home (tests).
func NewMesh(home string) *Mesh {
	return &Mesh{home: home, root: Open(home), links: map[string]*Link{}}
}

// Start runs one redial loop per chosen link until Stop.
func (m *Mesh) Start() {
	m.once.Do(func() {
		m.stop = make(chan struct{})
		go m.watch()
	})
}

// Stop ends the redial loops.
func (m *Mesh) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stop != nil {
		select {
		case <-m.stop:
		default:
			close(m.stop)
		}
	}
}

// Root is the single-phone link (pre-mesh scanner).
func (m *Mesh) Root() *Link { return m.root }

// Enabled reports whether the scanner runs one drop per phone.
func (m *Mesh) Enabled() bool {
	st, err := os.Stat(filepath.Join(m.home, "links"))
	return err == nil && st.IsDir()
}

func validCode(c string) bool {
	if len(c) != 8 {
		return false
	}
	for _, r := range c {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// ChosenCodes reads the chosen pairing codes, one per line, deduplicated,
// at most MaxLinks.
func ChosenCodes(home string) []string {
	raw, _ := os.ReadFile(filepath.Join(home, "chosen"))
	var out []string
	seen := map[string]bool{}
	for _, f := range strings.Fields(string(raw)) {
		f = strings.ToLower(f)
		if !validCode(f) || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
		if len(out) == MaxLinks {
			break
		}
	}
	return out
}

// WriteChosen stores codes, one per line.
func WriteChosen(home string, codes []string) error {
	var b strings.Builder
	n := 0
	for _, c := range codes {
		if validCode(c) && n < MaxLinks {
			b.WriteString(c + "\n")
			n++
		}
	}
	_ = os.MkdirAll(home, 0o700)
	return writeAtomic(filepath.Join(home, "chosen"), []byte(b.String()))
}

// Link is the per-phone link for one pairing code.
func (m *Mesh) Link(code string) *Link {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l := m.links[code]; l != nil {
		return l
	}
	l := openLink(m.home, filepath.Join(m.home, "links", code))
	m.links[code] = l
	return l
}

// Links is every chosen per-phone link, by code.
func (m *Mesh) Links() map[string]*Link {
	out := map[string]*Link{}
	if !m.Enabled() {
		return out
	}
	for _, c := range ChosenCodes(m.home) {
		out[c] = m.Link(c)
	}
	return out
}

// ForKey is a slot key routed per vote to its pinned phone.
func (m *Mesh) ForKey(label string, pub []byte) (*KeyLink, error) {
	k, err := m.root.ForKey(label, pub)
	if err != nil {
		return nil, err
	}
	k.m = m
	return k, nil
}

// route is the link that may carry a vote for label now.
func (m *Mesh) route(label string) (*Link, error) {
	if !m.Enabled() {
		return m.root, nil
	}
	slotMu.Lock()
	pin, _, err := slotPin(m.home, label)
	slotMu.Unlock()
	if err != nil {
		return nil, err
	}
	if pin == nil {
		return nil, fmt.Errorf("bluetooth: no phone is pinned for %s", label)
	}
	links := m.Links()
	codes := make([]string, 0, len(links))
	for c := range links {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	for _, c := range codes {
		l := links[c]
		if l.SessionUp() && bytes.Equal(l.sessionRemote(), pin) {
			return l, nil
		}
	}
	// Not up: wake the links that are (or may be) that phone. Never wait.
	for _, c := range codes {
		l := links[c]
		if r := l.Remote(); len(r) == 0 || bytes.Equal(r, pin) {
			l.kick()
		}
	}
	return nil, fmt.Errorf("%w (phone %s for %s)", ErrPhoneNotReady, Fingerprint(pin), label)
}

// LinkFor is the link where the phone with Noise static pub answers
// (session up, or its last handshake), or nil.
func (m *Mesh) LinkFor(pub []byte) *Link {
	if !m.Enabled() {
		return m.root
	}
	var maybe *Link
	for _, l := range m.Links() {
		if l.SessionUp() && bytes.Equal(l.sessionRemote(), pub) {
			return l
		}
		if bytes.Equal(l.Remote(), pub) {
			maybe = l
		}
	}
	return maybe
}

func (l *Link) sessionRemote() []byte {
	l.sessMu.Lock()
	defer l.sessMu.Unlock()
	if l.sess == nil {
		return nil
	}
	return append([]byte(nil), l.sess.RemoteStatic...)
}

// Drop forgets a link's session (its phone went away); others are untouched.
func (l *Link) Drop() {
	l.sessMu.Lock()
	l.sess = nil
	l.sessMu.Unlock()
}

type redial struct {
	next    time.Time
	backoff time.Duration
}

func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)*3/10+1))
}

// watch keeps every chosen link's session up, each on its own schedule.
func (m *Mesh) watch() {
	state := map[*Link]*redial{}
	t := time.NewTicker(meshTick)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
		}
		now := time.Now()
		for _, l := range m.Links() {
			st := state[l]
			if st == nil {
				st = &redial{}
				state[l] = st
			}
			m.rmu.Lock()
			if l.SessionUp() {
				st.backoff = 0
				m.rmu.Unlock()
				continue
			}
			wait := now.Before(st.next)
			m.rmu.Unlock()
			if wait || !l.handshaking.CompareAndSwap(false, true) {
				continue
			}
			go func(l *Link, st *redial) {
				defer l.handshaking.Store(false)
				err := l.handshakeNow()
				unpinned := false
				if r := l.Remote(); err != nil && len(r) == 32 && !authorized(m.home, r) {
					unpinned = true
				}
				m.rmu.Lock()
				defer m.rmu.Unlock()
				if err == nil {
					st.backoff = 0
					return
				}
				if unpinned {
					st.next = time.Now().Add(jitter(unpinnedRetry))
					return
				}
				switch {
				case st.backoff == 0:
					st.backoff = redialBase
				case st.backoff*2 > RedialMax:
					st.backoff = RedialMax
				default:
					st.backoff *= 2
				}
				st.next = time.Now().Add(jitter(st.backoff))
			}(l, st)
		}
	}
}

func authorized(home string, pub []byte) bool {
	slotMu.Lock()
	defer slotMu.Unlock()
	return anySlotPinned(home, pub)
}

// SessionStatic is the Noise static of the phone this link holds a session
// with, or nil.
func (l *Link) SessionStatic() []byte { return l.sessionRemote() }

// Code is the pairing code of a mesh link ("" for the root link).
func (l *Link) Code() string {
	if l.dir == l.home {
		return ""
	}
	return filepath.Base(l.dir)
}

// Recent is every link's recent signatures, oldest first.
func (m *Mesh) Recent() []SignRecord {
	all := m.root.Recent()
	for _, l := range m.Links() {
		all = append(all, l.Recent()...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].At < all[j].At })
	if len(all) > 64 {
		all = all[len(all)-64:]
	}
	return all
}
