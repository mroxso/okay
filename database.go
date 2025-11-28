package main

import (
	"database/sql"
	"fmt"
	"net"

	_ "github.com/lib/pq"
	"github.com/nbd-wtf/go-nostr/nip86"
)

// DBManager handles the normal PostgreSQL connection for non-event data
type DBManager struct {
	db *sql.DB
}

// NewDBManager creates a new database manager using an existing *sql.DB
// (for example from the khatru eventstore backend). It does not take
// ownership of the connection and therefore does not Close it.
func NewDBManager(existing *sql.DB) (*DBManager, error) {
	if existing == nil {
		return nil, fmt.Errorf("existing db cannot be nil")
	}

	manager := &DBManager{db: existing}
	if err := manager.initTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize database tables: %w", err)
	}

	return manager, nil
}

// initTables creates the necessary tables for the application.
// This method is called automatically during DBManager initialization.
func (dbm *DBManager) initTables() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS allowed_pubkeys (
			pubkey VARCHAR(64) PRIMARY KEY,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS banned_pubkeys (
			pubkey VARCHAR(64) PRIMARY KEY,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS events_needing_moderation (
			id VARCHAR(64) PRIMARY KEY,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS allowed_events (
			id VARCHAR(64) PRIMARY KEY,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS banned_events (
			id VARCHAR(64) PRIMARY KEY,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS allowed_kinds (
			kind INTEGER PRIMARY KEY,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS disallowed_kinds (
			kind INTEGER PRIMARY KEY,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS blocked_ips (
			ip INET PRIMARY KEY,
			reason TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS admins (
			pubkey VARCHAR(64) PRIMARY KEY,
			methods TEXT[],
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS relay_info (
			key VARCHAR(64) PRIMARY KEY,
			value TEXT,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range tables {
		if _, err := dbm.db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

// AddAllowedPubkey adds a pubkey to the allowed list with an optional reason.
// If the pubkey already exists, the operation is ignored (no error returned).
func (dbm *DBManager) AddAllowedPubkey(pubkey, reason string) error {
	if pubkey == "" {
		return fmt.Errorf("pubkey cannot be empty")
	}

	query := `INSERT INTO allowed_pubkeys (pubkey, reason) VALUES ($1, $2) ON CONFLICT (pubkey) DO NOTHING`
	if _, err := dbm.db.Exec(query, pubkey, reason); err != nil {
		return fmt.Errorf("failed to add allowed pubkey %s: %w", pubkey, err)
	}

	return nil
}

// RemoveAllowedPubkey removes a pubkey from the allowed list.
// Returns an error if the pubkey is not found in the allowed list.
func (dbm *DBManager) RemoveAllowedPubkey(pubkey string) error {
	if pubkey == "" {
		return fmt.Errorf("pubkey cannot be empty")
	}

	query := `DELETE FROM allowed_pubkeys WHERE pubkey = $1`
	result, err := dbm.db.Exec(query, pubkey)
	if err != nil {
		return fmt.Errorf("failed to remove allowed pubkey %s: %w", pubkey, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected for pubkey %s: %w", pubkey, err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("pubkey %s not found in allowed list", pubkey)
	}

	return nil
}

// IsAllowedPubkey checks if a pubkey is in the allowed list.
// Returns true if the pubkey is allowed, false otherwise.
func (dbm *DBManager) IsAllowedPubkey(pubkey string) (bool, error) {
	if pubkey == "" {
		return false, nil
	}

	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM allowed_pubkeys WHERE pubkey = $1)`
	if err := dbm.db.QueryRow(query, pubkey).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check if pubkey %s is allowed: %w", pubkey, err)
	}

	return exists, nil
}

// GetAllowedPubkeys returns all allowed pubkeys ordered by creation time.
// Returns an empty slice if no pubkeys are found.
func (dbm *DBManager) GetAllowedPubkeys() ([]string, error) {
	query := `SELECT pubkey FROM allowed_pubkeys ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query allowed pubkeys: %w", err)
	}
	defer rows.Close()

	var pubkeys []string
	for rows.Next() {
		var pubkey string
		if err := rows.Scan(&pubkey); err != nil {
			return nil, fmt.Errorf("failed to scan pubkey row: %w", err)
		}
		pubkeys = append(pubkeys, pubkey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error occurred while iterating over pubkey rows: %w", err)
	}

	return pubkeys, nil
}

// Close closes the database connection.
// This should be called when the DBManager is no longer needed.
func (dbm *DBManager) Close() error {
	if dbm.db != nil {
		// DBManager doesn't own the shared *sql.DB, so don't close it.
	}
	return nil
}

// Health checks the database connection health.
// Returns nil if the connection is healthy, an error otherwise.
func (dbm *DBManager) Health() error {
	if dbm.db == nil {
		return fmt.Errorf("database connection is nil")
	}

	if err := dbm.db.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

// BanPubKey adds a pubkey to the banned list.
func (dbm *DBManager) BanPubKey(pubkey, reason string) error {
	if pubkey == "" {
		return fmt.Errorf("pubkey cannot be empty")
	}
	query := `INSERT INTO banned_pubkeys (pubkey, reason) VALUES ($1, $2) ON CONFLICT (pubkey) DO UPDATE SET reason = $2`
	_, err := dbm.db.Exec(query, pubkey, reason)
	return err
}

// GetBannedPubkeys returns all banned pubkeys.
func (dbm *DBManager) GetBannedPubkeys() ([]nip86.PubKeyReason, error) {
	query := `SELECT pubkey, reason FROM banned_pubkeys ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nip86.PubKeyReason
	for rows.Next() {
		var pr nip86.PubKeyReason
		if err := rows.Scan(&pr.PubKey, &pr.Reason); err != nil {
			return nil, err
		}
		result = append(result, pr)
	}
	return result, rows.Err()
}

// GetAllowedPubkeysWithReason returns all allowed pubkeys with reasons.
func (dbm *DBManager) GetAllowedPubkeysWithReason() ([]nip86.PubKeyReason, error) {
	query := `SELECT pubkey, reason FROM allowed_pubkeys ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nip86.PubKeyReason
	for rows.Next() {
		var pr nip86.PubKeyReason
		if err := rows.Scan(&pr.PubKey, &pr.Reason); err != nil {
			return nil, err
		}
		result = append(result, pr)
	}
	return result, rows.Err()
}

// AddEventNeedingModeration adds an event to the moderation queue.
func (dbm *DBManager) AddEventNeedingModeration(id, reason string) error {
	if id == "" {
		return fmt.Errorf("event id cannot be empty")
	}
	query := `INSERT INTO events_needing_moderation (id, reason) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`
	_, err := dbm.db.Exec(query, id, reason)
	return err
}

// GetEventsNeedingModeration returns all events needing moderation.
func (dbm *DBManager) GetEventsNeedingModeration() ([]nip86.IDReason, error) {
	query := `SELECT id, reason FROM events_needing_moderation ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nip86.IDReason
	for rows.Next() {
		var ir nip86.IDReason
		if err := rows.Scan(&ir.ID, &ir.Reason); err != nil {
			return nil, err
		}
		result = append(result, ir)
	}
	return result, rows.Err()
}

// AllowEvent adds an event to the allowed list and removes it from moderation queue.
func (dbm *DBManager) AllowEvent(id, reason string) error {
	if id == "" {
		return fmt.Errorf("event id cannot be empty")
	}
	tx, err := dbm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO allowed_events (id, reason) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET reason = $2`, id, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM events_needing_moderation WHERE id = $1`, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM banned_events WHERE id = $1`, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// BanEvent adds an event to the banned list and removes it from moderation queue.
func (dbm *DBManager) BanEvent(id, reason string) error {
	if id == "" {
		return fmt.Errorf("event id cannot be empty")
	}
	tx, err := dbm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO banned_events (id, reason) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET reason = $2`, id, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM events_needing_moderation WHERE id = $1`, id)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM allowed_events WHERE id = $1`, id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// GetBannedEvents returns all banned events.
func (dbm *DBManager) GetBannedEvents() ([]nip86.IDReason, error) {
	query := `SELECT id, reason FROM banned_events ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nip86.IDReason
	for rows.Next() {
		var ir nip86.IDReason
		if err := rows.Scan(&ir.ID, &ir.Reason); err != nil {
			return nil, err
		}
		result = append(result, ir)
	}
	return result, rows.Err()
}

// GetAllowedEvents returns all allowed events.
func (dbm *DBManager) GetAllowedEvents() ([]nip86.IDReason, error) {
	query := `SELECT id, reason FROM allowed_events ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nip86.IDReason
	for rows.Next() {
		var ir nip86.IDReason
		if err := rows.Scan(&ir.ID, &ir.Reason); err != nil {
			return nil, err
		}
		result = append(result, ir)
	}
	return result, rows.Err()
}

// AllowKind adds a kind to the allowed list.
func (dbm *DBManager) AllowKind(kind int) error {
	tx, err := dbm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO allowed_kinds (kind) VALUES ($1) ON CONFLICT (kind) DO NOTHING`, kind)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM disallowed_kinds WHERE kind = $1`, kind)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// DisallowKind adds a kind to the disallowed list.
func (dbm *DBManager) DisallowKind(kind int) error {
	tx, err := dbm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO disallowed_kinds (kind) VALUES ($1) ON CONFLICT (kind) DO NOTHING`, kind)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM allowed_kinds WHERE kind = $1`, kind)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// GetAllowedKinds returns all allowed kinds.
func (dbm *DBManager) GetAllowedKinds() ([]int, error) {
	query := `SELECT kind FROM allowed_kinds ORDER BY kind`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []int
	for rows.Next() {
		var kind int
		if err := rows.Scan(&kind); err != nil {
			return nil, err
		}
		result = append(result, kind)
	}
	return result, rows.Err()
}

// GetDisallowedKinds returns all disallowed kinds.
func (dbm *DBManager) GetDisallowedKinds() ([]int, error) {
	query := `SELECT kind FROM disallowed_kinds ORDER BY kind`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []int
	for rows.Next() {
		var kind int
		if err := rows.Scan(&kind); err != nil {
			return nil, err
		}
		result = append(result, kind)
	}
	return result, rows.Err()
}

// BlockIP adds an IP to the blocked list.
func (dbm *DBManager) BlockIP(ip net.IP, reason string) error {
	if ip == nil {
		return fmt.Errorf("ip cannot be nil")
	}
	query := `INSERT INTO blocked_ips (ip, reason) VALUES ($1, $2) ON CONFLICT (ip) DO UPDATE SET reason = $2`
	_, err := dbm.db.Exec(query, ip.String(), reason)
	return err
}

// UnblockIP removes an IP from the blocked list.
func (dbm *DBManager) UnblockIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("ip cannot be nil")
	}
	query := `DELETE FROM blocked_ips WHERE ip = $1`
	_, err := dbm.db.Exec(query, ip.String())
	return err
}

// GetBlockedIPs returns all blocked IPs.
func (dbm *DBManager) GetBlockedIPs() ([]nip86.IPReason, error) {
	query := `SELECT ip, reason FROM blocked_ips ORDER BY created_at`
	rows, err := dbm.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []nip86.IPReason
	for rows.Next() {
		var ir nip86.IPReason
		if err := rows.Scan(&ir.IP, &ir.Reason); err != nil {
			return nil, err
		}
		result = append(result, ir)
	}
	return result, rows.Err()
}

// SetRelayInfo sets a relay info field (name, description, icon).
func (dbm *DBManager) SetRelayInfo(key, value string) error {
	query := `INSERT INTO relay_info (key, value, updated_at) VALUES ($1, $2, CURRENT_TIMESTAMP) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`
	_, err := dbm.db.Exec(query, key, value)
	return err
}

// GetRelayInfo gets a relay info field.
func (dbm *DBManager) GetRelayInfo(key string) (string, error) {
	var value string
	query := `SELECT value FROM relay_info WHERE key = $1`
	err := dbm.db.QueryRow(query, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// GrantAdmin grants admin permissions to a pubkey.
func (dbm *DBManager) GrantAdmin(pubkey string, methods []string) error {
	if pubkey == "" {
		return fmt.Errorf("pubkey cannot be empty")
	}
	query := `INSERT INTO admins (pubkey, methods) VALUES ($1, $2) ON CONFLICT (pubkey) DO UPDATE SET methods = $2`
	_, err := dbm.db.Exec(query, pubkey, methods)
	return err
}

// RevokeAdmin revokes admin permissions from a pubkey.
func (dbm *DBManager) RevokeAdmin(pubkey string, methods []string) error {
	if pubkey == "" {
		return fmt.Errorf("pubkey cannot be empty")
	}
	if len(methods) == 0 {
		// If no methods specified, revoke all admin access
		query := `DELETE FROM admins WHERE pubkey = $1`
		_, err := dbm.db.Exec(query, pubkey)
		return err
	}
	// Otherwise, update methods list
	var currentMethods []string
	query := `SELECT methods FROM admins WHERE pubkey = $1`
	err := dbm.db.QueryRow(query, pubkey).Scan(&currentMethods)
	if err == sql.ErrNoRows {
		return nil // Already not an admin
	}
	if err != nil {
		return err
	}
	// Remove specified methods
	methodMap := make(map[string]bool)
	for _, m := range currentMethods {
		methodMap[m] = true
	}
	for _, m := range methods {
		delete(methodMap, m)
	}
	newMethods := make([]string, 0, len(methodMap))
	for m := range methodMap {
		newMethods = append(newMethods, m)
	}
	if len(newMethods) == 0 {
		query = `DELETE FROM admins WHERE pubkey = $1`
		_, err = dbm.db.Exec(query, pubkey)
		return err
	}
	query = `UPDATE admins SET methods = $1 WHERE pubkey = $2`
	_, err = dbm.db.Exec(query, newMethods, pubkey)
	return err
}

// IsAdmin checks if a pubkey is an admin.
func (dbm *DBManager) IsAdmin(pubkey string) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM admins WHERE pubkey = $1)`
	err := dbm.db.QueryRow(query, pubkey).Scan(&exists)
	return exists, err
}

// GetAdminMethods returns the admin methods for a pubkey.
func (dbm *DBManager) GetAdminMethods(pubkey string) ([]string, error) {
	var methods []string
	query := `SELECT methods FROM admins WHERE pubkey = $1`
	err := dbm.db.QueryRow(query, pubkey).Scan(&methods)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return methods, err
}
