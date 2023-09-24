package sigchain

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/ssh"
	"os"
	"tasadar.net/tionis/ssh-tools/certs"
)

type Sigchain struct {
	TrustedKeys []ssh.PublicKey
}

func (s *Sigchain) VerifyCert(cert *certs.Cert) error {
	// TODO verify cert
	err := cert.Verify(s.TrustedKeys)
	if err != nil {
		return fmt.Errorf("failed to verify cert: %w", err)
	}
	return nil
}

func New(path string, trustAnchor sql.NullString) (*Sigchain, error) {
	_, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// TODO parse fileData
	return &Sigchain{}, nil
}

type MultiAddrTranscoder struct{}

func (m MultiAddrTranscoder) StringToBytes(s string) ([]byte, error) {
	return []byte(s), nil
}

func (m MultiAddrTranscoder) BytesToString(b []byte) (string, error) {
	return string(b), nil
}

func (m MultiAddrTranscoder) ValidateBytes(b []byte) error {
	if bytes.IndexByte(b, '/') >= 0 {
		// TODO handle more illegal chars
		return fmt.Errorf("domain name %q contains a slash", string(b))
	}
	return nil
}

func MultiAddrParse(str string) (multiaddr.Multiaddr, error) {
	err := multiaddr.AddProtocol(
		multiaddr.Protocol{
			Name:       "sigchain",
			Code:       285,
			VCode:      multiaddr.CodeToVarint(285),
			Size:       -1,
			Path:       false,
			Transcoder: MultiAddrTranscoder{},
		})
	if err != nil {
		return nil, fmt.Errorf("failed to add sigchain protocol: %w", err)
	}
	sigchainAddr, err := multiaddr.NewMultiaddr(str)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sigchain: %w", err)
	}
	marshal, err := json.MarshalIndent(sigchainAddr.Protocols(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sigchain: %w", err)
	}
	fmt.Println(string(marshal))
	marshalJSON, err := sigchainAddr.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sigchain: %w", err)
	}
	fmt.Println(string(marshalJSON))
	return sigchainAddr, nil
}
