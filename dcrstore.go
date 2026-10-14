package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "modernc.org/sqlite"

	"github.com/luikyv/go-oidc/pkg/goidc"
)

const maxRedirectURIs = 10

type sqliteDCRManager struct{ db *sql.DB }

func (m *sqliteDCRManager) SaveClient(_ context.Context, c *goidc.Client) error {
	metaJSON, err := json.Marshal(c.ClientMeta)
	if err != nil {
		return err
	}
	_, err = m.db.Exec(
		"INSERT OR REPLACE INTO clients (client_id, meta_json, created_at) VALUES (?, ?, ?)",
		c.ID, string(metaJSON), time.Now().Unix(),
	)
	return err
}

func (m *sqliteDCRManager) Client(_ context.Context, id string) (*goidc.Client, error) {
	var metaJSON string
	err := m.db.QueryRow("SELECT meta_json FROM clients WHERE client_id = ?", id).Scan(&metaJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, goidc.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var meta goidc.ClientMeta
	if err := json.Unmarshal([]byte(metaJSON), &meta); err != nil {
		return nil, err
	}
	return &goidc.Client{ID: id, ClientMeta: meta}, nil
}

func (m *sqliteDCRManager) DeleteClient(_ context.Context, id string) error {
	res, err := m.db.Exec("DELETE FROM clients WHERE client_id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return goidc.ErrNotFound
	}
	return nil
}

func newSQLiteDCRManager(path string) (*sqliteDCRManager, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS clients (
			client_id  TEXT PRIMARY KEY,
			meta_json  TEXT NOT NULL,
			created_at INTEGER NOT NULL
		)`); err != nil {
		return nil, err
	}
	return &sqliteDCRManager{db: db}, nil
}
