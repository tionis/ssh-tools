package sigchain

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"tasadar.net/tionis/ssh-tools/util"
)

type Entry struct {
	Hash           string
	AllowedSigners []util.AllowedSigner
	ParentHash     *string
	Signature      *string
}

type MarshalledEntryNoSig struct {
	AllowedSigners []util.MarshalledAllowedSigner `json:"allowed_signers"`
	ParentHash     *string                        `json:"parent_hash"`
}

type MarshalledEntry struct {
	AllowedSigners []util.MarshalledAllowedSigner `json:"allowed_signers"`
	ParentHash     *string                        `json:"parent_hash"`
	Signature      *string                        `json:"signature"`
}

func (entry *Entry) Marshal() (MarshalledEntry, error) {
	var marshalled MarshalledEntry
	for _, as := range entry.AllowedSigners {
		marshalledAS := as.Marshal()
		marshalled.AllowedSigners = append(marshalled.AllowedSigners, marshalledAS)
	}
	marshalled.ParentHash = entry.ParentHash
	marshalled.Signature = entry.Signature
	return marshalled, nil
}

func (m *MarshalledEntry) Unmarshal() (Entry, error) {
	var entry Entry
	for _, mas := range m.AllowedSigners {
		as, err := mas.Unmarshal()
		if err != nil {
			return Entry{}, fmt.Errorf("could not unmarshal allowed signer: %w", err)
		}
		entry.AllowedSigners = append(entry.AllowedSigners, as)
	}
	entry.ParentHash = m.ParentHash
	entry.Signature = m.Signature
	return entry, nil
}

func (m *MarshalledEntry) GetHash() (string, error) {
	marshal, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("could not marshal entry: %w", err)
	}
	rawHash := sha256.Sum256(marshal)
	return fmt.Sprintf("%x", rawHash), nil
}

func ParseSigchain(rawSigchain []byte) ([]Entry, error) {
	var entries []MarshalledEntry
	err := json.Unmarshal(rawSigchain, &entries)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal sigchain: %w", err)
	}
	var parsedEntries map[string]Entry
	for _, marshalledEntry := range entries {
		var entry Entry
		entry, err = marshalledEntry.Unmarshal()
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal entry: %w", err)
		}
		parsedEntries[entry.Hash] = entry
	}
	return nil, errors.New("not implemented")
}

// ApplySigchain applies a new sigchain delta to the database.
func (m *Manager) ApplySigchain(rawSigchain []byte) (updatedAnchors []string, err error) {
	sigchain, err := ParseSigchain(rawSigchain)
	if err != nil {
		return nil, fmt.Errorf("could not parse sigchain: %w", err)
	}
	for _, entry := range sigchain {
		return nil, errors.New("not implemented yet")
		// TODO verify signature against parent if present
		data, err := entry.Marshal()
		if err != nil {
			return nil, fmt.Errorf("could not marshal sigchain entry: %w", err)
		}
		_, err = m.db.ExecContext(m.ctx, "INSERT INTO sigchain_entries (hash, data) VALUES (?, ?);", entry.Hash, data)
		if err != nil {
			return nil, fmt.Errorf("could not insert sigchain entry: %w", err)
		}
	}
	var updatedNamespaces map[string]bool
	for i := len(sigchain) - 1; i >= 0; i-- {
		entry := sigchain[i]
		rows, err := m.db.QueryContext(
			m.ctx,
			"SELECT namespace, timestamp FROM trust_anchors WHERE hash = ?;",
			entry.Hash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, fmt.Errorf("could not get trust anchors: %w", err)
		}
		for rows.Next() {
			var namespace string
			var timestamp int
			err = rows.Scan(&namespace, &timestamp)
			// skip check if namespace was already updated
			if !updatedNamespaces[namespace] {
				if err != nil {
					return nil, fmt.Errorf("could not scan trust anchor: %w", err)
				}
				// Query the newest trust anchor for the namespace
				var newestTimestamp int
				err = m.db.QueryRowContext(
					m.ctx,
					"SELECT timestamp FROM trust_anchors WHERE namespace = ? ORDER BY timestamp DESC LIMIT 1;",
					namespace).Scan(&newestTimestamp)
				if err != nil {
					return nil, fmt.Errorf("could not get newest trust anchor: %w", err)
				}
				if newestTimestamp != timestamp {
					return nil, fmt.Errorf("possible downgrade attack: %s", namespace)
				}
				updatedNamespaces[namespace] = true
				_, err = m.db.ExecContext(
					m.ctx,
					"INSERT INTO trust_anchors (namespace, timestamp, hash) VALUES (?, ?, ?);",
					namespace, timestamp, entry.Hash)
				if err != nil {
					return nil, fmt.Errorf("could not insert trust anchor: %w", err)
				}
			}
		}
		err = rows.Close()
		if err != nil {
			return nil, fmt.Errorf("could not close rows: %w", err)
		}
	}
	var nameSpaceList []string
	for namespace := range updatedNamespaces {
		nameSpaceList = append(nameSpaceList, namespace)
	}
	return nameSpaceList, nil
}

func (m *Manager) getOwnSigchain() (Entry, error) {
	var ownNamespace string
	err := m.db.QueryRowContext(m.ctx, "SELECT value FROM kv WHERE key = 'ownNamespace';").Scan(&ownNamespace)
	if err != nil {
		return Entry{}, fmt.Errorf("could not get own namespace: %w", err)
	}
	var hash, data string
	err = m.db.QueryRowContext(
		m.ctx,
		`SELECT hash, data
              FROM sigchain_entries
              WHERE hash = (SELECT hash FROM trust_anchors WHERE namespace = ? ORDER BY timestamp DESC LIMIT 1);`,
		ownNamespace).Scan(&hash, &data)
	if err != nil {
		return Entry{}, fmt.Errorf("could not get own sigchain: %w", err)
	}
	var marshalledEntry MarshalledEntry
	err = json.Unmarshal([]byte(data), &marshalledEntry)
	if err != nil {
		return Entry{}, fmt.Errorf("could not unmarshal own sigchain: %w", err)
	}
	var entry Entry
	entry, err = marshalledEntry.Unmarshal()
	if err != nil {
		return Entry{}, fmt.Errorf("could not unmarshal own sigchain: %w", err)
	}
	return entry, nil
}
