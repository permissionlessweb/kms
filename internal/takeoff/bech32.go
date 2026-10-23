package takeoff

import "fmt"

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Encode(hrp string, data []byte) (string, error) {
	conv, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	return encode(hrp, conv)
}

func bech32Decode(s string) (string, []byte, error) {
	hrp, data, err := decode(s)
	if err != nil {
		return "", nil, err
	}
	raw, err := convertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	if len(raw) > 20 {
		raw = raw[:20]
	}
	return hrp, raw, nil
}

func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	acc := 0
	bits := uint(0)
	maxv := (1 << to) - 1
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)
	for _, value := range data {
		acc = (acc << from) | int(value)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad && bits > 0 {
		out = append(out, byte((acc<<(to-bits))&maxv))
	}
	return out, nil
}

func encode(hrp string, data []byte) (string, error) {
	chk := polymod(append(hrpExpand(hrp), append(data, 0, 0, 0, 0, 0, 0)...)) ^ 1
	ret := hrp + "1"
	for _, b := range data {
		ret += string(charset[b])
	}
	for i := 0; i < 6; i++ {
		ret += string(charset[(chk>>uint(5*(5-i)))&31])
	}
	return ret, nil
}

func decode(s string) (string, []byte, error) {
	pos := -1
	for i, c := range s {
		if c == '1' {
			pos = i
		}
	}
	if pos < 1 {
		return "", nil, fmt.Errorf("takeoff: bad bech32")
	}
	hrp := s[:pos]
	data := make([]byte, 0, len(s)-pos-1)
	for _, c := range s[pos+1:] {
		idx := -1
		for i := 0; i < len(charset); i++ {
			if rune(charset[i]) == c {
				idx = i
				break
			}
		}
		if idx < 0 {
			return "", nil, fmt.Errorf("takeoff: bad bech32")
		}
		data = append(data, byte(idx))
	}
	if len(data) < 6 {
		return "", nil, fmt.Errorf("takeoff: short bech32")
	}
	payload := data[:len(data)-6]
	return hrp, payload, nil
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

func polymod(values []byte) int {
	chk := 1
	gen := []int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range values {
		b := chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ int(v)
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}
