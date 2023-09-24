package yubikey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/ssh"
	"io"
	"sync"
	"tasadar.net/tionis/ssh-tools/util"
	"tasadar.net/tionis/ssh-tools/util/prompt"
	"time"
)

type Key struct {
	mu      sync.Mutex
	yk      *piv.YubiKey
	serial  uint32
	pubKey  ssh.PublicKey
	privKey crypto.PrivateKey
	signer  ssh.Signer
	// touchNotification is armed by Sign to show a notification if waiting for
	// more than a few seconds for the touch operation. It is paused and reset
	// by getPIN, so it won't fire while waiting for the PIN.
	touchNotification *time.Timer
}

func (k *Key) GetPIN() (string, error) {
	if k.touchNotification != nil && k.touchNotification.Stop() {
		defer k.touchNotification.Reset(5 * time.Second)
	}
	r, err := k.yk.Retries()
	if err != nil {
		return "", fmt.Errorf("failed to get retries: %w", err)
	}
	return prompt.GetPIN(k.serial, r)
}

func GetPublicKey(yk *piv.YubiKey, slot piv.Slot) (ssh.PublicKey, error) {
	cert, err := yk.Certificate(slot)
	if err != nil {
		return nil, fmt.Errorf("could not get public key: %w", err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
	case *rsa.PublicKey:
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", cert.PublicKey)
	}
	pk, err := ssh.NewPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to process public key: %w", err)
	}
	return pk, nil
}

func (k *Key) PublicKey() ssh.PublicKey {
	return k.pubKey
}

func (k *Key) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	signed, err := k.signer.Sign(rand, data)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k.touchNotification = time.NewTimer(5 * time.Second)
	go func() {
		select {
		case <-k.touchNotification.C:
		case <-ctx.Done():
			k.touchNotification.Stop()
			return
		}
		util.ShowNotification("Waiting for YubiKey touch...")
	}()
	if err != nil {
		return nil, err
	}
	return signed, err
}

func New() (*Key, error) {
	ykRaw, err := openYK()
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %w", err)
	}
	serial, err := ykRaw.Serial()
	if err != nil {
		return nil, err
	}
	pk, err := GetPublicKey(ykRaw, piv.SlotSignature)
	if err != nil {
		return nil, err
	}
	k := &Key{
		yk:                ykRaw,
		serial:            serial,
		pubKey:            pk,
		privKey:           nil,
		signer:            nil,
		touchNotification: nil,
	}
	priv, err := ykRaw.PrivateKey(
		piv.SlotSignature,
		pk.(ssh.CryptoPublicKey).CryptoPublicKey(),
		piv.KeyAuth{PINPrompt: k.GetPIN},
	)
	if err != nil {
		return nil, err
	}
	k.privKey = priv
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare signer: %w", err)
	}
	k.signer = s
	return k, nil
}

func openYK() (yk *piv.YubiKey, err error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	// TODO: support multiple YubiKeys. For now, select the first one that opens
	// successfully, to skip any internal unused smart card readers.
	for _, card := range cards {
		yk, err = piv.Open(card)
		if err == nil {
			return
		}
	}
	return
}
