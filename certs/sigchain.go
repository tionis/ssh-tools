package certs

import (
	"golang.org/x/crypto/ssh"
	"time"
)

type TrustedCA struct {
	From       time.Time
	To         time.Time
	Principals []string // TODO implement as trie for wildcard matching
}

type VerifyConfig struct {
	trustedCAs  map[ssh.PublicKey]TrustedCA
	revokedKeys map[ssh.PublicKey]bool
}

func NewVerifyConfig() *VerifyConfig {
	// TODO load from file
	// TODO verify sigchain
	return &VerifyConfig{
		trustedCAs:  make(map[ssh.PublicKey]TrustedCA),
		revokedKeys: make(map[ssh.PublicKey]bool),
	}
}
