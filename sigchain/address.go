package sigchain

import (
	"fmt"
	"strings"
)

type Address struct {
	RootHash       []byte
	ConnectionType string
	ConnectionAddr string
}

func AddrParse(str string) (*Address, error) {
	parts := strings.Split(str, "/")
	if len(parts) < 4 {
		return nil, fmt.Errorf("invalid sigchain addr (too short): %q", str)
	}
	if parts[0] != "sigchain" {
		return nil, fmt.Errorf("invalid sigchain addr (wrong prefix): %q", str)
	}
	return &Address{
		RootHash:       []byte(parts[1]),
		ConnectionType: parts[2],
		ConnectionAddr: strings.Join(parts[3:], "/"),
	}, nil
}
