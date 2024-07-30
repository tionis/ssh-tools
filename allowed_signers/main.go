package allowed_signers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strings"
	"github.com/tionis/ssh-tools/allowed_signers/glob"
	"time"
)

// TODO refactor this into more manageable subpackages/files

var keyAlgos = map[string]bool{
	ssh.KeyAlgoDSA:        true,
	ssh.KeyAlgoRSA:        true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoRSASHA512:  true,
	ssh.KeyAlgoRSASHA256:  true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoSKED25519:  true,
}

func splitAtComma(str string) []string {
	parts := strings.Split(str, ",")
	finalParts := make([]string, 0)

	for _, part := range parts {
		if strings.HasSuffix(part, "\\") {
			finalParts[len(finalParts)-1] += "," + strings.TrimSuffix(part, "\\")
		} else {
			finalParts = append(finalParts, part)
		}
	}

	return finalParts
}

func splitAtSpacesExceptInQuotes(in []byte) [][]byte {
	var res [][]byte
	var beg int
	var inQuotes bool

	for i := 0; i < len(in); i++ {
		if in[i] == ' ' && !inQuotes {
			res = append(res, in[beg:i])
			beg = i + 1
		} else if in[i] == '"' {
			if !inQuotes {
				inQuotes = true
			} else if i > 0 && in[i-1] != '\\' {
				inQuotes = false
			}
		}
	}
	return append(res, in[beg:])
}

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
// TODO check if this parses correctly in all cases
func ParseAllowedSigner(in []byte) (principals []string, options []string, pubKey ssh.PublicKey, comment *string, rest []byte, err error) {
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
		keyFields := splitAtSpacesExceptInQuotes(in)
		hasOptions := true
		if _, ok := keyAlgos[string(keyFields[1])]; ok {
			hasOptions = false
		}

		// The first field is the principal list.
		principals := string(keyFields[0])

		// If there are 4 fields, the second field is the options list.
		var options string
		if hasOptions {
			options = string(keyFields[1])
		}

		// keyFields[len(keyFields)-2] contains the key type (e.g. "sha-rsa").
		// This information is also available in the base64-encoded key, and
		// thus ignored here.
		var key []byte
		if hasOptions {
			key = bytes.Join(keyFields[3:], []byte(" "))
		} else {
			key = bytes.Join(keyFields[2:], []byte(" "))
		}

		// the format does not allow a comment, but openssh allows it in practice
		var commentStr string
		if pubKey, commentStr, err = parseAuthorizedKey(key); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		comment = &commentStr // TODO that's a bit ugly
		var optionsArr []string
		if len(options) > 0 {
			optionsArr = strings.Split(options, ",")
		}
		return strings.Split(principals, ","), optionsArr, pubKey, comment, rest, nil
	}
	return nil, nil, nil, nil, nil, io.EOF
}

func parseAuthorizedKey(in []byte) (out ssh.PublicKey, comment string, err error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, "", err
	}
	key = key[:n]
	out, err = ssh.ParsePublicKey(key)
	if err != nil {
		return nil, "", err
	}
	comment = string(bytes.TrimSpace(in[i:]))
	return out, comment, nil
}

type TrustChecker struct {
	Entries        map[string]AllowedSignerEntry
	CertChecker    ssh.CertChecker
	AuthorizedKeys map[string]authorizedKey
	//KnownHosts     map[string]knownHost // TODO https://github.com/skeema/knownhosts
}

type AllowedSignerEntry struct {
	Principals       []string
	principalChecker func(string) sql.NullString
	IsCA             bool
	Namespaces       []string
	nameSpaceChecker func(string) sql.NullString
	Comment          *string
	ValidAfter       sql.NullTime
	ValidBefore      sql.NullTime
}

func (a AllowedSignerEntry) NameSpaceAllowed(namespace string) bool {
	matched := a.nameSpaceChecker(namespace)
	return matched.Valid
}

func (a AllowedSignerEntry) PrincipalsAllowed(namespace string) bool {
	matched := a.principalChecker(namespace)
	return matched.Valid
}

func parseTime(s string) (result time.Time, err error) {
	// format: YYYYMMDD[Z] or YYYYMMDDHHMM[SS][Z]
	var loc *time.Location
	utc := strings.HasSuffix(s, "Z")
	timestamp := strings.TrimSuffix(s, "Z")
	if utc {
		loc = time.UTC
	} else {
		loc = time.Local
	}
	switch len(timestamp) {
	case 8:
		result, err = time.ParseInLocation("20060102", timestamp, loc)
	case 12:
		result, err = time.ParseInLocation("200601021504", timestamp, loc)
	case 14:
		result, err = time.ParseInLocation("20060102150405", timestamp, loc)
	default:
		return time.Time{}, errors.New("invalid timestamp")
	}
	return
}

func parseOptions(options []string) (isCA bool, namespaces []string, validAfter sql.NullTime, validBefore sql.NullTime, err error) {
	for _, option := range options {
		if option == "cert-authority" {
			isCA = true
		} else if strings.HasPrefix(option, "namespaces=") {
			if option[11] == '"' {
				namespaces = splitAtComma(option[12 : len(option)-1])
			} else {
				namespaces = splitAtComma(option[11:])
			}
		} else if strings.HasPrefix(option, "valid-after=") {
			var timestamp string
			validAfter.Valid = true
			if option[12] == '"' {
				timestamp = option[13 : len(option)-1]
			} else {
				timestamp = option[12:]
			}
			validAfter.Valid = true
			validAfter.Time, err = parseTime(timestamp)
			if err != nil {
				return false, nil, sql.NullTime{}, sql.NullTime{}, fmt.Errorf("failed to parse valid-after: %w", err)
			}
		} else if strings.HasPrefix(option, "valid-before=") {
			var timestamp string
			validBefore.Valid = true
			if option[13] == '"' {
				timestamp = option[14 : len(option)-1]
			} else {
				timestamp = option[13:]
			}
			validBefore.Time, err = parseTime(timestamp)
			if err != nil {
				return false, nil, sql.NullTime{}, sql.NullTime{}, fmt.Errorf("failed to parse valid-before: %w", err)
			}
		} else {
			return false, nil, sql.NullTime{}, sql.NullTime{}, fmt.Errorf("unknown option: %s", option)
		}
	}
	return
}

type authorizedKey struct {
	PubKey  ssh.PublicKey
	Comment string
	Options []string
}

func ParseAuthorizedKeys(b []byte) ([]authorizedKey, error) {
	var keys []authorizedKey
	for len(b) > 0 {
		pubKey, comment, options, rest, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			return nil, err
		}
		keys = append(keys, authorizedKey{
			PubKey:  pubKey,
			Comment: comment,
			Options: options, // TODO actually parse authorizedKeys options here (maybe map to ssh.Permissions?)
		})
		b = rest
	}
	return keys, nil
}

// ParseAllowedSigners parses an allowed_signers file.
func GetTrust(allowedSigners, authorizedKeys, knownHosts []byte) (TrustChecker, error) {
	keyMap := make(map[string]AllowedSignerEntry)
	for len(allowedSigners) > 0 {
		principals, options, pubkey, comment, rest, err := ParseAllowedSigner(allowedSigners)
		if err != nil {
			return TrustChecker{}, fmt.Errorf("failed to parse allowed signer: %w", err)
		}
		isCA, namespaces, validAfter, validBefore, err := parseOptions(options)
		if err != nil {
			return TrustChecker{}, fmt.Errorf("failed to parse options: %w", err)
		}
		nameSpaceChecker, err := glob.GetListMatcher(namespaces)
		if err != nil {
			return TrustChecker{}, fmt.Errorf("failed to create namespace matcher: %w", err)
		}
		principalChecker, err := glob.GetListMatcher(principals)
		if err != nil {
			return TrustChecker{}, fmt.Errorf("failed to create principal matcher: %w", err)
		}
		keyMap[string(pubkey.Marshal())] = AllowedSignerEntry{
			Principals:       principals,
			principalChecker: principalChecker,
			IsCA:             isCA,
			Namespaces:       namespaces,
			nameSpaceChecker: nameSpaceChecker,
			Comment:          comment,
			ValidAfter:       validAfter,
			ValidBefore:      validBefore,
		}
		allowedSigners = rest
	}
	keys, err := ParseAuthorizedKeys(authorizedKeys)
	if err != nil {
		return TrustChecker{}, err
	}
	authorizedKeysMap := make(map[string]authorizedKey)
	for key := range keys {
		authorizedKeysMap[string(keys[key].PubKey.Marshal())] = keys[key]
	}
	trust := TrustChecker{
		AuthorizedKeys: authorizedKeysMap,
		Entries:        keyMap,
		CertChecker: ssh.CertChecker{
			IsRevoked: func(cert *ssh.Certificate) bool {
				// TODO handle revocations here
				return false
			},
			IsUserAuthority: func(auth ssh.PublicKey) bool {
				if _, ok := keyMap[string(auth.Marshal())]; ok {
					return true
				}
				return false
			},
			IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
				if _, ok := keyMap[string(auth.Marshal())]; ok {
					return true
				}
				return false
			},
			Clock: time.Now,
			UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				// TODO parse authorized_keys file for this
				// or allow generation of an authorized_keys pattern from the allowed_signers file
				// allow to define principals and restrictions for them
				return nil, errors.New("not implemented")
			},
			HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				// TODO parse known_hosts file for this
				return errors.New("not implemented")
			},
		},
	}
	return trust, nil
}

func (a *TrustChecker) VerifySignature(m io.Reader, sig *sshsig.Signature, hashAlgorithm sshsig.HashAlgorithm, principal, namespace string, atTime sql.NullTime) error {
	var pubKey ssh.PublicKey
	switch sig.PublicKey.(type) {
	case *ssh.Certificate:
		cert := sig.PublicKey.(*ssh.Certificate)
		err := a.CertChecker.CheckCert(principal, cert)
		if err != nil {
			return fmt.Errorf("failed to verify cert: %w", err)
		}
		if _, ok := a.Entries[string(cert.SignatureKey.Marshal())]; !ok {
			return errors.New("no matching signing key for cert found")
		}
		principalMatcher, err := glob.GetListMatcher(cert.ValidPrincipals)
		if err != nil {
			return fmt.Errorf("failed to create principal matcher: %w", err)
		}
		principalMatch := principalMatcher(principal)
		if !principalMatch.Valid {
			return errors.New("principal not allowed in cert")
		}
		if _, ok := cert.Extensions["namespaces"]; ok {
			// TODO ensure namespaces extension is supported everywhere else
			namespaceMatcher, err := glob.GetListMatcher(splitAtComma(cert.Extensions["namespaces"]))
			if err != nil {
				return fmt.Errorf("failed to create namespace matcher: %w", err)
			}
			namespaceMatch := namespaceMatcher(namespace)
			if !namespaceMatch.Valid {
				return errors.New("namespace not allowed in cert")
			}
		}
		pubKey = cert.SignatureKey
	default:
		pubKey = sig.PublicKey
	}
	keyInfo, ok := a.Entries[string(pubKey.Marshal())]
	if !ok {
		return errors.New("no matching key found")
	}
	if !keyInfo.NameSpaceAllowed(namespace) {
		return errors.New("namespace not allowed")
	}
	if !keyInfo.PrincipalsAllowed(principal) {
		return errors.New("principal not allowed")
	}
	if atTime.Valid {
		if keyInfo.ValidAfter.Valid && atTime.Time.Before(keyInfo.ValidAfter.Time) {
			return errors.New("signature not valid yet")
		}
		if keyInfo.ValidBefore.Valid && atTime.Time.After(keyInfo.ValidBefore.Time) {
			return errors.New("signature expired")
		}
	}
	err := sshsig.Verify(m, sig, sig.PublicKey, hashAlgorithm, namespace)
	if err != nil {
		return fmt.Errorf("failed to verify signature: %w", err)
	}
	return nil
}

func (a *TrustChecker) Render() ([]byte, error) {
	var buf bytes.Buffer
	for marshalledKey, entry := range a.Entries {
		key, err := ssh.ParsePublicKey([]byte(marshalledKey))
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal key: %w", err)
		}
		buf.WriteString(strings.Join(entry.Principals, ","))
		buf.WriteRune(' ')
		if entry.IsCA {
			buf.WriteString("cert-authority,")
		}
		if len(entry.Namespaces) > 0 {
			buf.WriteString("namespaces=")
			buf.WriteString(strings.Join(entry.Namespaces, ","))
			buf.WriteRune(',')
		}
		if entry.ValidAfter.Valid {
			buf.WriteString("valid-after=")
			// keep timezone information?
			buf.WriteString(entry.ValidAfter.Time.UTC().Format("20060102150405Z"))
			buf.WriteRune(',')
		}
		if entry.ValidBefore.Valid {
			buf.WriteString("valid-before=")
			// keep timezone information?
			buf.WriteString(entry.ValidBefore.Time.UTC().Format("20060102150405Z"))
			buf.WriteRune(',')
		}
		// remove last comma
		buf.Truncate(buf.Len() - 1)
		buf.WriteRune(' ')
		buf.Write([]byte(key.Type()))
		buf.WriteRune(' ')
		buf.Write([]byte(base64.StdEncoding.EncodeToString(key.Marshal())))
		if entry.Comment != nil {
			buf.WriteRune(' ')
			buf.WriteString(*entry.Comment)
		}
		buf.WriteRune('\n')
	}
	return buf.Bytes(), nil
}
