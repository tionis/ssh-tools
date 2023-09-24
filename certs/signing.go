package certs

import (
	"golang.org/x/crypto/ssh"
	"time"
)

type SigningConfig struct {
	CAKey                       ssh.Signer
	ClockInaccuracyCompensation time.Duration
	IgnoreExpiry                bool
	RevokedKeys                 map[ssh.PublicKey]bool
}

func (conf *SigningConfig) WasRevoked(cert *ssh.Certificate) bool {
	if conf.RevokedKeys == nil {
		return false
	}
	if conf.RevokedKeys[cert.SignatureKey] {
		return true
	}
	return false
}
