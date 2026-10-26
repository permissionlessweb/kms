package uiserver

import (
	"errors"
	"strings"
)

// Owner derivation (bech32 helpers shared with ownerkey.go): a validator operator address (terpvaloper1…) and its
// owner account (terp1…) carry the same bytes; only the HRP differs.

// bech32Decode returns the HRP and 5-bit data (checksum stripped).
func bech32Decode(s string) (string, []byte, error) {
	if strings.ToLower(s) != s && strings.ToUpper(s) != s {
		return "", nil, errors.New("bech32: mixed case")
	}
	s = strings.ToLower(s)
	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return "", nil, errors.New("bech32: bad separator")
	}
	hrp := s[:pos]
	data := make([]byte, 0, len(s)-pos-1)
	for _, c := range s[pos+1:] {
		i := strings.IndexRune(bech32Charset, c)
		if i < 0 {
			return "", nil, errors.New("bech32: bad character")
		}
		data = append(data, byte(i))
	}
	if bech32Polymod(append(hrpExpand(hrp), data...)) != 1 {
		return "", nil, errors.New("bech32: bad checksum")
	}
	return hrp, data[:len(data)-6], nil
}

// OwnerFromValoper re-encodes a valoper address with the account prefix:
// the HRP minus a trailing "valoper" (terpvaloper1… -> terp1…, same bytes).
func OwnerFromValoper(valoper string) (string, error) {
	hrp, data, err := bech32Decode(strings.TrimSpace(valoper))
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(hrp, "valoper") || len(hrp) == len("valoper") {
		return "", errors.New("not a valoper address: " + hrp)
	}
	b, err := convertBits(data, 5, 8, false)
	if err != nil {
		return "", err
	}
	return bech32Encode(strings.TrimSuffix(hrp, "valoper"), b), nil
}
