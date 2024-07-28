package sigchain

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strconv"
)

type Manager struct {
	db     *sql.DB
	logger *slog.Logger
	ctx    context.Context
}

var migrations = []string{
	`CREATE TABLE sigchain_entries (
  hash TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  validated BOOLEAN DEFAULT FALSE NOT NULL,
  created_at INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL,
  CHECK(json_valid(data, 6))
) STRICT;
CREATE INDEX sigchain_entries_parent_hash ON sigchain_entries((data->>'$parent_hash$'));
CREATE TABLE trust_anchors (
  namespace TEXT NOT NULL,
  timestamp INTEGER DEFAULT (strftime('%s', 'now')) NOT NULL,
  hash TEXT REFERENCES sigchain_entries(hash),
  PRIMARY KEY (namespace, timestamp)
) STRICT;
CREATE INDEX trust_anchors_ref_hash ON trust_anchors(hash);
CREATE TABLE kv ( -- to be used for some config settings, as a cache etc
  key TEXT PRIMARY KEY,
  value TEXT
) STRICT;`,
}

func (m *Manager) applyMigrations() error {
	for {
		query, err := m.db.Query("PRAGMA user_version;")
		if err != nil {
			return fmt.Errorf("could not get user_version: %w", err)
		}
		var version int
		if !query.Next() {
			return fmt.Errorf("could not get user_version")
		}
		err = query.Scan(&version)
		if err != nil {
			return fmt.Errorf("could not get user_version: %w", err)
		}
		err = query.Close()
		if err != nil {
			return fmt.Errorf("could not close query: %w", err)
		}
		if version >= len(migrations) {
			break
		}
		m.logger.Info("Applying migration", "version", version)
		_, err = m.db.ExecContext(m.ctx,
			"BEGIN TRANSACTION;"+
				migrations[version]+
				"PRAGMA user_version = "+strconv.Itoa(version+1)+";"+
				"COMMIT;")
		if err != nil {
			return fmt.Errorf("could not apply migration: %w", err)
		}
		m.logger.Info("Migration applied", "version", version)
	}
	return nil
}

func NewSigchainManager(ctx context.Context, dbPath string, logger *slog.Logger) (*Manager, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on&_journal_mode=WAL&_synchronous=normal&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("could not open database: %w", err)
	}
	m := &Manager{db: db, logger: logger, ctx: ctx}
	err = m.applyMigrations()
	if err != nil {
		return nil, fmt.Errorf("could not apply migrations: %w", err)
	}
	return m, nil
}

func (m *Manager) Close() error {
	return m.db.Close()
}
