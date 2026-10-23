package takeoff

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
)

const minimals = "aeadaoaxaaahamatayasbkbdbnbtbabsbebybgbwbbbzcmchcscfcycwcecackctcxclcpcndkdadsdidedtdrdndwdpdmdldyeheyeoeeecenemetesftfrfnfsfmfhfzfpfwfxfyfefgflfdgagegrgsgtglgwgdgygmgughgohfhghdhkhthphhhlhyhehnhsidiaieihiyioisinimjejzjnjtjljojsjpjkjykpkoktkskkknkgkekikblblalylflslrlplnltloldlelulklgmnmymhmemomumwmdmtmsmknlnyndnsntnnnenboyoeotoxonolospdptpkpypspmplpepfpaprqdqzrerprlrorhrdrkrfryrnrsrtsesasrssskswstspsosgsbsfsntotktitttdtetytltbtstptatnuyuoutueurvtvyvovlvevwvavdvswlwdwmwpwewywswtwnwzwfwkykynylyaytzszoztzczezm"

// decodeCworch reads one ur:cworch-sig code into the pubkey and signature.
func DecodeCworch(raw string) ([]byte, []byte, error) {
	text := strings.ToLower(strings.TrimSpace(raw))
	const prefix = "ur:cworch-sig/"
	if !strings.HasPrefix(text, prefix) {
		return nil, nil, fmt.Errorf("takeoff: signature QR is not ur:cworch-sig")
	}
	body, err := decodeMinimal(strings.TrimPrefix(text, prefix))
	if err != nil {
		return nil, nil, err
	}
	if len(body) < 4 {
		return nil, nil, fmt.Errorf("takeoff: signature QR is short")
	}
	payload, sum := body[:len(body)-4], body[len(body)-4:]
	if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(sum) {
		return nil, nil, fmt.Errorf("takeoff: signature QR checksum")
	}
	if len(payload) != 97 {
		return nil, nil, fmt.Errorf("takeoff: signature QR is %d bytes", len(payload))
	}
	return append([]byte(nil), payload[:33]...), append([]byte(nil), payload[33:]...), nil
}

func decodeMinimal(body string) ([]byte, error) {
	if len(minimals) != 512 {
		return nil, fmt.Errorf("takeoff: byteword table")
	}
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("takeoff: signature QR length")
	}
	out := make([]byte, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		word := body[i : i+2]
		found := -1
		for n := 0; n < 256; n++ {
			if minimals[n*2:n*2+2] == word {
				found = n
				break
			}
		}
		if found < 0 {
			return nil, fmt.Errorf("takeoff: signature QR word")
		}
		out = append(out, byte(found))
	}
	return out, nil
}

func encodeMinimal(data []byte) string {
	sum := crc32.ChecksumIEEE(data)
	var tail [4]byte
	binary.BigEndian.PutUint32(tail[:], sum)
	all := append(append([]byte(nil), data...), tail[:]...)
	var b strings.Builder
	for _, by := range all {
		b.WriteString(minimals[int(by)*2 : int(by)*2+2])
	}
	return b.String()
}
