package allowed_signers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hiddeco/sshsig"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ParseAllowedSigner parses an entry in the format of the allowed_signers file.
//
// The allowed_signers format is documented in the ssh-keygen(1) manual page.
// This function will parse a single entry from in. On successful return,
// principals will contain the list of principals that this entry matches,
// options will contain the list of options that this entry matches (i.e.
// "cert-authority", "namespaces=file,git"), and pubKey will contain the
// public key. See the ssh-keygen(1) manual page for the various forms that a
// principal string can take, and further details on the options.
//
// The unparsed remainder of the input will be returned in rest. This function
// can be called repeatedly to parse multiple entries.
//
// If no entries were found in the input then err will be io.EOF. Otherwise, a
// non-nil err value indicates a parse error.
//
// This function is an addition to the golang.org/x/crypto/ssh package, which
// does offer ssh.ParseAuthorizedKey and ssh.ParseKnownHosts, but not a parser
// for allowed_signers files which has a slightly different format.
func ParseAllowedSigner(in []byte) (principals []string, options []string, pubKey ssh.PublicKey, rest []byte, err error) {
	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		// Split the line into the principal list, options, and key.
		// The options are not required, and may not be present.
		keyFields := bytes.Fields(in)
		if len(keyFields) < 3 || len(keyFields) > 4 {
			return nil, nil, nil, nil, errors.New("ssh: invalid entry in allowed_signers data")
		}

		// The first field is the principal list.
		principals := string(keyFields[0])

		// If there are 4 fields, the second field is the options list.
		var options string
		if len(keyFields) == 4 {
			options = string(keyFields[1])
		}

		// TODO parse optional comment at the end (not specified in the standard, but still parsed by openssh)

		// keyFields[len(keyFields)-2] contains the key type (e.g. "sha-rsa").
		// This information is also available in the base64-encoded key, and
		// thus ignored here.
		key := bytes.Join(keyFields[len(keyFields)-1:], []byte(" "))
		if pubKey, err = parseAuthorizedKey(key); err != nil {
			return nil, nil, nil, nil, err
		}
		return strings.Split(principals, ","), strings.Split(options, ","), pubKey, rest, nil
	}
	return nil, nil, nil, nil, io.EOF
}

// parseAuthorizedKey parses a public key in OpenSSH authorized_keys format
// (see sshd(8) manual page) once the options and key type fields have been
// removed.
//
// This function is a modified copy of the parseAuthorizedKey function from the
// golang.org/x/crypto/ssh package, and does not return any comments.
//
// xref: https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.7.0:ssh/keys.go;l=88?q=parseAuthorizedKey
func parseAuthorizedKey(in []byte) (out ssh.PublicKey, err error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, err
	}
	key = key[:n]
	out, err = ssh.ParsePublicKey(key)
	if err != nil {
		return nil, err
	}
	return out, nil
}

type AllowedSigners struct {
	Entries map[ssh.PublicKey]AllowedSignerEntry
}

type AllowedSignerEntry struct {
	Principals []string
	IsCA 	 bool
	Namespaces []string
	Comment string
	ValidAfter sql.NullTime
	ValidBefore sql.NullTime
}

func (a AllowedSignerEntry) NameSpaceAllowed(namespace string) bool {
	for _, opt := range a.Principals {
		if opt == namespace {
			return true
		}
		// TODO handle globs
	}
	return false
}

func (a AllowedSignerEntry) PrincipalsAllowed(namespace string) bool {
	for _, opt := range a.Principals {
		if opt == namespace {
			return true
		}
		// TODO handle globs
	}
	return false
}

// ParseAllowedSigners parses an allowed_signers file.
func ParseAllowedSigners(b []byte) (AllowedSigners, error) {
	keyMap := make(map[ssh.PublicKey]AllowedSignerEntry)
	for len(b) > 0 {
		principals, options, pubkey, rest, err := ParseAllowedSigner(b)
		if err != nil {
			return AllowedSigners{}, fmt.Errorf("failed to parse allowed signer: %w", err)
		}
		isCA, namespaces, validAfter, validBefore, err := parseOptions(options)
		if err != nil {
			return AllowedSigners{}, fmt.Errorf("failed to parse options: %w", err)
		}
		keyMap[pubkey] = AllowedSignerEntry{
			Principals: principals,
			IsCA: isCA,
			Namespaces: namespaces,
			Comment: "",
			ValidAfter: validAfter,
			ValidBefore: validBefore,
		}
		b = rest
	}
	// TODO do some processing to handle principal matching more efficiently
	return AllowedSigners{
		Entries: keyMap,
	}, nil
}

func (a AllowedSigners) VerifyCert(cert *ssh.Certificate) error {
	// TODO verify cert
	return nil
}

func (a AllowedSigners) VerifySignature(m io.Reader, sig *sshsig.Signature, hashAlgorithm sshsig.HashAlgorithm, namespace string) error {
	keyInfo, ok := a.Entries[sig.PublicKey]
	if !ok {
		// TODO handle certs
		// TODO check in cert if namespace is allowed (use special option in cert)
		return errors.New("no matching key found")
	}
	if !keyInfo.NameSpaceAllowed(namespace) {
		return errors.New("namespace not allowed")
	}
	// TODO handle time using valid-after and valid-before
	err := sshsig.Verify(m, sig, sig.PublicKey, hashAlgorithm, namespace)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	return nil
}

func (a *AllowedSigners)

// TODO render to allowed_signers file
