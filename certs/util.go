package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
	"github.com/tionis/ssh-tools/yubikey"
	"time"
)

func GetTemporaryRootKey(signingConf SigningConfig) (ssh.Signer, error) {
	pubKey, signer, err := GetSSHKeyPair()
	if err != nil {
		return nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	cert := DefaultUserCert()
	cert.SetPrincipals([]string{"root", "tionis.dev", "*"})
	cert.SetIdentifier(hostname + "@tionis.dev")
	cert.SetValidAfter(time.Now().Add(-1 * time.Minute))
	cert.SetValidBefore(time.Now().Add(1 * time.Minute))
	cert.SetKey(pubKey)

	err = cert.Sign(signingConf)
	if err != nil {
		return nil, fmt.Errorf("failed to sign temporary cert: %w", err)
	}

	return cert.AttachCertToSigner(signer)
}

func GetSSHKeyPair() (ssh.PublicKey, ssh.Signer, error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ssh key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ssh signer: %w", err)
	}
	return sshPubKey, signer, nil
}

func CreateSigningConf(clockCompensation time.Duration, IgnoreExpiry bool) (SigningConfig, error) {
	caKey, err := yubikey.New()
	if err != nil {
		log.Println("failed to get caKey: ", err)
		return SigningConfig{}, fmt.Errorf("failed to get caKey: %w", err)
	}
	return SigningConfig{
		CAKey:                       caKey,
		IgnoreExpiry:                IgnoreExpiry,
		ClockInaccuracyCompensation: clockCompensation,
		RevokedKeys:                 map[ssh.PublicKey]bool{}, // TODO load revocation list from somewhere
	}, nil
}
