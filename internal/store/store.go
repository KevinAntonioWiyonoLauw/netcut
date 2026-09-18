// language: Go, file: internal/store/store.go
//
// SQLite persistence.
//
// Timestamp convention: every time column is an INTEGER holding Unix
// milliseconds, with 0 meaning "unset". Storing times as numbers rather than
// SQL TIMESTAMP strings keeps the schema portable across SQLite drivers and
// removes any dependence on how a driver happens to render a date, which is
// the usual source of silent scan failures.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store is the SQLite-backed persistence layer.
type Store struct {
	db *sql.DB
}

// Open creates or opens the database at path and applies the schema.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// WAL allows concurrent readers; a small pool is plenty and avoids
	// writer contention on a single-file database.
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	s := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// ---------- time helpers ----------

// tms converts a time to Unix milliseconds, mapping the zero time to 0.
func tms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UTC().UnixMilli()
}

// fromMS converts Unix milliseconds back to a time, mapping 0 to the zero time.
func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

// nowMS is the current time in the stored representation.
func nowMS() int64 { return time.Now().UTC().UnixMilli() }

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer',
    created_at    INTEGER NOT NULL DEFAULT 0,
    last_login    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    mac          TEXT PRIMARY KEY,
    ip           TEXT NOT NULL DEFAULT '',
    hostname     TEXT NOT NULL DEFAULT '',
    vendor       TEXT NOT NULL DEFAULT '',
    alias        TEXT NOT NULL DEFAULT '',
    grp          TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    online       INTEGER NOT NULL DEFAULT 0,
    protected    INTEGER NOT NULL DEFAULT 0,
    blocked      INTEGER NOT NULL DEFAULT 0,
    throttled    INTEGER NOT NULL DEFAULT 0,
    arp_poisoned INTEGER NOT NULL DEFAULT 0,
    rx_bps       INTEGER NOT NULL DEFAULT 0,
    tx_bps       INTEGER NOT NULL DEFAULT 0,
    rtt_ms       REAL    NOT NULL DEFAULT 0,
    packets      INTEGER NOT NULL DEFAULT 0,
    bytes_rx     INTEGER NOT NULL DEFAULT 0,
    bytes_tx     INTEGER NOT NULL DEFAULT 0,
    first_seen   INTEGER NOT NULL DEFAULT 0,
    last_seen    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_ip  ON devices(ip);
CREATE INDEX IF NOT EXISTS idx_devices_grp ON devices(grp);

CREATE TABLE IF NOT EXISTS policies (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_value TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    cap_kbps     INTEGER NOT NULL DEFAULT 0,
    up_kbps      INTEGER NOT NULL DEFAULT 0,
    schedule     TEXT NOT NULL DEFAULT '',
    window       TEXT NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    priority     INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL DEFAULT 0,
    created_by   TEXT NOT NULL DEFAULT '',
    last_applied INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority DESC);

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL DEFAULT 0,
    type     TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    mac      TEXT NOT NULL DEFAULT '',
    message  TEXT NOT NULL,
    actor    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts  ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_mac ON events(mac);

CREATE TABLE IF NOT EXISTS samples (
    ts     INTEGER NOT NULL,
    mac    TEXT NOT NULL,
    rx_bps INTEGER NOT NULL,
    tx_bps INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_mac_ts ON samples(mac, ts DESC);

CREATE TABLE IF NOT EXISTS agent_tokens (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL DEFAULT 0,
    last_seen  INTEGER NOT NULL DEFAULT 0,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_overrides (
    mac        TEXT PRIMARY KEY,
    action     TEXT NOT NULL DEFAULT '',
    cap_kbps   INTEGER NOT NULL DEFAULT 0,
    up_kbps    INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT 0
);
`

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// ---------- users ----------

// CreateUser inserts a new account.
func (s *Store) CreateUser(ctx context.Context, u *model.User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id,email,password_hash,role,created_at,last_login) VALUES (?,?,?,?,?,?)`,
		u.ID, strings.ToLower(u.Email), u.PasswordHash, string(u.Role), tms(u.CreatedAt), tms(u.LastLogin))
	return err
}

// UpsertUser creates the user if absent, otherwise leaves it untouched.
func (s *Store) UpsertUser(ctx context.Context, u *model.User) (created bool, err error) {
	_, err = s.UserByEmail(ctx, u.Email)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return false, err
	}
	return true, s.CreateUser(ctx, u)
}

const userCols = `id,email,password_hash,role,created_at,last_login`

func scanUser(sc interface{ Scan(...any) error }) (*model.User, error) {
	var u model.User
	var role string
	var created, lastLogin int64
	err := sc.Scan(&u.ID, &u.Email, &u.PasswordHash, &role, &created, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Role = model.Role(role)
	u.CreatedAt = fromMS(created)
	u.LastLogin = fromMS(lastLogin)
	if u.LastLogin.IsZero() {
		u.LastLogin = u.CreatedAt
	}
	return &u, nil
}

// UserByEmail looks up an account by email address.
func (s *Store) UserByEmail(ctx context.Context, email string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE email = ? COLLATE NOCASE`, strings.TrimSpace(email))
	return scanUser(row)
}

// UserByID looks up an account by id.
func (s *Store) UserByID(ctx context.Context, id string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// ListUsers returns all accounts.
func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UpdateUserRole changes an account's role.
func (s *Store) UpdateUserRole(ctx context.Context, id string, role model.Role) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET role=? WHERE id=?`, string(role), id)
	return affected(res, err)
}

// UpdateUserPassword sets a new password hash.
func (s *Store) UpdateUserPassword(ctx context.Context, id, hash string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return affected(res, err)
}

// DeleteUser removes an account.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id)
	return affected(res, err)
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, nowMS(), id)
	return err
}

// CountUsers returns the number of accounts.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountOwners returns the number of owner accounts.
func (s *Store) CountOwners(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE role = ?`, string(model.RoleOwner)).Scan(&n)
	return n, err
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------- devices ----------

const deviceCols = `mac,ip,hostname,vendor,alias,grp,note,online,protected,blocked,
throttled,arp_poisoned,rx_bps,tx_bps,rtt_ms,packets,bytes_rx,bytes_tx,first_seen,last_seen`

func scanDevice(sc interface{ Scan(...any) error }) (*model.Device, error) {
	var d model.Device
	var first, last int64
	err := sc.Scan(&d.MAC, &d.IP, &d.Hostname, &d.Vendor, &d.Alias, &d.Group, &d.Note,
		&d.Online, &d.Protected, &d.Blocked, &d.Throttled, &d.ArpPoisoned,
		&d.RxBps, &d.TxBps, &d.RTTms, &d.Packets, &d.BytesRx, &d.BytesTx,
		&first, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	d.FirstSeen = fromMS(first)
	d.LastSeen = fromMS(last)
	return &d, nil
}

// UpsertDevice inserts a newly discovered device or refreshes its identity
// fields. Operator-owned fields (alias, group, note, protected, blocked,
// throttled) are never clobbered by a scan.
func (s *Store) UpsertDevice(ctx context.Context, d *model.Device) error {
	// Normalise the key first: an agent may report a MAC in any of the
	// dash/colon/case spellings, and the primary key must be canonical or
	// lookups silently miss.
	d.MAC = normMAC(d.MAC)
	if d.MAC == "" {
		return errors.New("device MAC is required")
	}
	now := time.Now().UTC()
	if d.FirstSeen.IsZero() {
		d.FirstSeen = now
	}
	if d.LastSeen.IsZero() {
		d.LastSeen = now
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO devices (`+deviceCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET
			ip        = CASE WHEN excluded.ip       <> '' THEN excluded.ip       ELSE devices.ip       END,
			hostname  = CASE WHEN excluded.hostname <> '' THEN excluded.hostname ELSE devices.hostname END,
			vendor    = CASE WHEN excluded.vendor   <> '' THEN excluded.vendor   ELSE devices.vendor   END,
			online    = excluded.online,
			last_seen = excluded.last_seen`,
		d.MAC, d.IP, d.Hostname, d.Vendor, d.Alias, d.Group, d.Note,
		d.Online, d.Protected, d.Blocked, d.Throttled, d.ArpPoisoned,
		d.RxBps, d.TxBps, d.RTTms, d.Packets, d.BytesRx, d.BytesTx,
		tms(d.FirstSeen), tms(d.LastSeen))
	return err
}

// UpdateDeviceRuntime writes live telemetry and the resolved enforcement state
// for a device.
func (s *Store) UpdateDeviceRuntime(ctx context.Context, d *model.Device) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE devices SET ip=?, online=?, arp_poisoned=?, blocked=?, throttled=?,
			rx_bps=?, tx_bps=?, rtt_ms=?, packets=?, bytes_rx=?, bytes_tx=?, last_seen=?
		WHERE mac=?`,
		d.IP, d.Online, d.ArpPoisoned, d.Blocked, d.Throttled,
		d.RxBps, d.TxBps, d.RTTms, d.Packets, d.BytesRx, d.BytesTx,
		nowMS(), d.MAC)
	return err
}

// Device returns one device by MAC.
func (s *Store) Device(ctx context.Context, mac string) (*model.Device, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices WHERE mac=?`, normMAC(mac))
	return scanDevice(row)
}

// ListDevices returns every known device.
func (s *Store) ListDevices(ctx context.Context) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+deviceCols+` FROM devices ORDER BY online DESC, last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// UpdateDeviceSettings writes the operator-controlled per-device fields.
func (s *Store) UpdateDeviceSettings(ctx context.Context, d *model.Device) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE devices SET alias=?, grp=?, note=?, protected=?, blocked=?, throttled=?
		WHERE mac=?`,
		d.Alias, d.Group, d.Note, d.Protected, d.Blocked, d.Throttled, d.MAC)
	return affected(res, err)
}

// SetDeviceFlag toggles a single boolean operator flag on a device.
func (s *Store) SetDeviceFlag(ctx context.Context, mac, field string, value bool) error {
	allowed := map[string]bool{"protected": true, "blocked": true, "throttled": true}
	if !allowed[field] {
		return fmt.Errorf("field %q is not a settable device flag", field)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET `+field+`=? WHERE mac=?`, value, normMAC(mac))
	return affected(res, err)
}

// MarkOfflineExcept flags every device not in keep as offline. Devices that
// were not seen in this scan window stop being reported as online.
func (s *Store) MarkOfflineExcept(ctx context.Context, keep []string) error {
	if len(keep) == 0 {
		_, err := s.db.ExecContext(ctx, `UPDATE devices SET online=0, rx_bps=0, tx_bps=0`)
		return err
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(keep)), ",")
	args := make([]any, 0, len(keep))
	for _, k := range keep {
		args = append(args, normMAC(k))
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE devices SET online=0, rx_bps=0, tx_bps=0 WHERE mac NOT IN (`+placeholders+`)`, args...)
	return err
}

// ForgetDevice removes a device and its history.
func (s *Store) ForgetDevice(ctx context.Context, mac string) error {
	mac = normMAC(mac)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM samples WHERE mac=?`,
		`DELETE FROM device_overrides WHERE mac=?`,
		`DELETE FROM devices WHERE mac=?`,
	} {
		if _, err := tx.ExecContext(ctx, q, mac); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ProtectedMACs returns the MAC addresses exempt from enforcement.
func (s *Store) ProtectedMACs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mac FROM devices WHERE protected=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return nil, err
		}
		out[normMAC(m)] = true
	}
	return out, rows.Err()
}

// ---------- policies ----------

const policyCols = `id,name,target_type,target_value,action,cap_kbps,up_kbps,
schedule,window,enabled,priority,created_at,created_by,last_applied`

func scanPolicy(sc interface{ Scan(...any) error }) (*model.Policy, error) {
	var p model.Policy
	var tt, act string
	var created, applied int64
	err := sc.Scan(&p.ID, &p.Name, &tt, &p.TargetValue, &act, &p.CapKbps, &p.UpKbps,
		&p.Schedule, &p.Window, &p.Enabled, &p.Priority, &created, &p.CreatedBy, &applied)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.TargetType = model.TargetType(tt)
	p.Action = model.Action(act)
	p.CreatedAt = fromMS(created)
	p.LastApplied = fromMS(applied)
	return &p, nil
}

// CreatePolicy inserts a policy.
func (s *Store) CreatePolicy(ctx context.Context, p *model.Policy) error {
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (`+policyCols+`)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ID, p.Name, string(p.TargetType), p.TargetValue, string(p.Action),
		p.CapKbps, p.UpKbps, p.Schedule, p.Window, p.Enabled, p.Priority,
		tms(p.CreatedAt), p.CreatedBy, tms(p.LastApplied))
	return err
}

// UpdatePolicy replaces a policy definition.
func (s *Store) UpdatePolicy(ctx context.Context, p *model.Policy) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE policies SET name=?, target_type=?, target_value=?, action=?,
			cap_kbps=?, up_kbps=?, schedule=?, window=?, enabled=?, priority=?
		WHERE id=?`,
		p.Name, string(p.TargetType), p.TargetValue, string(p.Action),
		p.CapKbps, p.UpKbps, p.Schedule, p.Window, p.Enabled, p.Priority, p.ID)
	return affected(res, err)
}

// DeletePolicy removes a policy.
func (s *Store) DeletePolicy(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM policies WHERE id=?`, id)
	return affected(res, err)
}

// ListPolicies returns policies ordered by priority, highest first.
func (s *Store) ListPolicies(ctx context.Context) ([]model.Policy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+policyCols+` FROM policies ORDER BY priority DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Policy returns a single policy.
func (s *Store) Policy(ctx context.Context, id string) (*model.Policy, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+policyCols+` FROM policies WHERE id=?`, id)
	return scanPolicy(row)
}

// TouchPolicyApplied records the last enforcement time.
func (s *Store) TouchPolicyApplied(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE policies SET last_applied=? WHERE id=?`, nowMS(), id)
	return err
}

// ---------- manual overrides ----------

// Override is a manual, per-device instruction that outranks policies until it
// expires or is cleared. This is the "change one device by hand" control.
type Override struct {
	MAC       string       `json:"mac"`
	Action    model.Action `json:"action"`
	CapKbps   int          `json:"cap_kbps"`
	UpKbps    int          `json:"up_kbps"`
	ExpiresAt *time.Time   `json:"expires_at,omitempty"`
	UpdatedBy string       `json:"updated_by"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// SetOverride writes a manual override for a device.
func (s *Store) SetOverride(ctx context.Context, o *Override) error {
	if o.UpdatedAt.IsZero() {
		o.UpdatedAt = time.Now().UTC()
	}
	var exp int64
	if o.ExpiresAt != nil {
		exp = tms(*o.ExpiresAt)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO device_overrides (mac,action,cap_kbps,up_kbps,expires_at,updated_by,updated_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(mac) DO UPDATE SET
			action=excluded.action, cap_kbps=excluded.cap_kbps, up_kbps=excluded.up_kbps,
			expires_at=excluded.expires_at, updated_by=excluded.updated_by,
			updated_at=excluded.updated_at`,
		normMAC(o.MAC), string(o.Action), o.CapKbps, o.UpKbps, exp, o.UpdatedBy, tms(o.UpdatedAt))
	return err
}

// ClearOverride removes a device's manual override.
func (s *Store) ClearOverride(ctx context.Context, mac string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM device_overrides WHERE mac=?`, normMAC(mac))
	return err
}

// ClearAllOverrides removes every manual override.
func (s *Store) ClearAllOverrides(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_overrides`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ActiveOverrides returns overrides that have not expired, keyed by MAC.
func (s *Store) ActiveOverrides(ctx context.Context) (map[string]Override, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT mac,action,cap_kbps,up_kbps,expires_at,updated_by,updated_at
		 FROM device_overrides
		 WHERE expires_at = 0 OR expires_at > ?`, nowMS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Override{}
	for rows.Next() {
		var o Override
		var act string
		var exp, updated int64
		if err := rows.Scan(&o.MAC, &act, &o.CapKbps, &o.UpKbps, &exp, &o.UpdatedBy, &updated); err != nil {
			return nil, err
		}
		o.Action = model.Action(act)
		o.UpdatedAt = fromMS(updated)
		if exp != 0 {
			t := fromMS(exp)
			o.ExpiresAt = &t
		}
		out[normMAC(o.MAC)] = o
	}
	return out, rows.Err()
}

// PurgeExpiredOverrides deletes overrides past their expiry.
func (s *Store) PurgeExpiredOverrides(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM device_overrides WHERE expires_at <> 0 AND expires_at <= ?`, nowMS())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------- events ----------

// AddEvent appends an audit entry.
func (s *Store) AddEvent(ctx context.Context, e *model.Event) error {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if e.Severity == "" {
		e.Severity = "info"
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO events (ts,type,severity,mac,message,actor) VALUES (?,?,?,?,?,?)`,
		tms(e.TS), e.Type, e.Severity, normMAC(e.MAC), e.Message, e.Actor)
	return err
}

// ListEvents returns the most recent events, newest first.
func (s *Store) ListEvents(ctx context.Context, limit int, mac string) ([]model.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id,ts,type,severity,mac,message,actor FROM events`
	args := []any{}
	if mac != "" {
		q += ` WHERE mac=?`
		args = append(args, normMAC(mac))
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Event
	for rows.Next() {
		var e model.Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Type, &e.Severity, &e.MAC, &e.Message, &e.Actor); err != nil {
			return nil, err
		}
		e.TS = fromMS(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneEvents keeps the log bounded.
func (s *Store) PruneEvents(ctx context.Context, keep int) error {
	_, err := s.db.ExecContext(ctx, `
		DELETE FROM events WHERE id NOT IN (
			SELECT id FROM events ORDER BY ts DESC, id DESC LIMIT ?
		)`, keep)
	return err
}

// ---------- samples ----------

// AddSamples writes bandwidth samples in one transaction.
func (s *Store) AddSamples(ctx context.Context, samples []model.Sample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO samples (ts,mac,rx_bps,tx_bps) VALUES (?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, sm := range samples {
		ts := sm.TS
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		if _, err := stmt.ExecContext(ctx, tms(ts), normMAC(sm.MAC), sm.RxBps, sm.TxBps); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Samples returns bandwidth samples for a MAC (or all MACs when empty) since a
// point in time.
func (s *Store) Samples(ctx context.Context, mac string, since time.Time) ([]model.Sample, error) {
	q := `SELECT ts,mac,rx_bps,tx_bps FROM samples WHERE ts >= ?`
	args := []any{tms(since)}
	if mac != "" {
		q += ` AND mac=?`
		args = append(args, normMAC(mac))
	}
	q += ` ORDER BY ts`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Sample
	for rows.Next() {
		var sm model.Sample
		var ts int64
		if err := rows.Scan(&ts, &sm.MAC, &sm.RxBps, &sm.TxBps); err != nil {
			return nil, err
		}
		sm.TS = fromMS(ts)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// PruneSamples drops samples older than cutoff.
func (s *Store) PruneSamples(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM samples WHERE ts < ?`, tms(cutoff))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------- agent tokens ----------

// CreateAgentToken stores the SHA-256 hash of an agent credential.
func (s *Store) CreateAgentToken(ctx context.Context, id, name, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO agent_tokens (id,name,token_hash,created_at) VALUES (?,?,?,?)`,
		id, name, tokenHash, nowMS())
	return err
}

// AgentTokenValid reports whether a credential digest is registered and not
// revoked.
func (s *Store) AgentTokenValid(ctx context.Context, tokenHash string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_tokens WHERE token_hash=? AND revoked=0`, tokenHash).Scan(&n)
	return n > 0, err
}

// TouchAgentToken records the last time an agent authenticated.
func (s *Store) TouchAgentToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE agent_tokens SET last_seen=? WHERE token_hash=?`, nowMS(), tokenHash)
	return err
}

// ListAgentTokens returns registered agents without their secrets.
func (s *Store) ListAgentTokens(ctx context.Context) ([]model.AgentToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,created_at,last_seen,revoked FROM agent_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AgentToken
	for rows.Next() {
		var t model.AgentToken
		var created, seen int64
		if err := rows.Scan(&t.ID, &t.Name, &created, &seen, &t.Revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = fromMS(created)
		t.LastSeen = fromMS(seen)
		if t.LastSeen.IsZero() {
			t.LastSeen = t.CreatedAt
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAgentToken disables an agent credential.
func (s *Store) RevokeAgentToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE agent_tokens SET revoked=1 WHERE id=?`, id)
	return affected(res, err)
}

// CountAgentTokens returns how many credentials exist.
func (s *Store) CountAgentTokens(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_tokens`).Scan(&n)
	return n, err
}

// ---------- settings ----------

// Setting reads a key from the settings table.
func (s *Store) Setting(ctx context.Context, key, def string) string {
	var v string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

// SetSetting writes a key into the settings table.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO settings (key,value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// Stats summarizes the fleet for the dashboard header.
type Stats struct {
	Devices    int    `json:"devices"`
	Online     int    `json:"online"`
	Blocked    int    `json:"blocked"`
	Throttled  int    `json:"throttled"`
	Protected  int    `json:"protected"`
	Policies   int    `json:"policies"`
	ActivePol  int    `json:"active_policies"`
	Events     int    `json:"events"`
	RxBpsTotal uint64 `json:"rx_bps_total"`
	TxBpsTotal uint64 `json:"tx_bps_total"`
}

// Stats computes aggregate counters.
func (s *Store) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{}
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(online),0),
		       COALESCE(SUM(blocked),0),
		       COALESCE(SUM(throttled),0),
		       COALESCE(SUM(protected),0),
		       COALESCE(SUM(rx_bps),0),
		       COALESCE(SUM(tx_bps),0)
		FROM devices`).Scan(&st.Devices, &st.Online, &st.Blocked,
		&st.Throttled, &st.Protected, &st.RxBpsTotal, &st.TxBpsTotal)
	if err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(enabled),0) FROM policies`).
		Scan(&st.Policies, &st.ActivePol); err != nil {
		return nil, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&st.Events); err != nil {
		return nil, err
	}
	return st, nil
}

// normMAC canonicalises a MAC address to lower-case colon form.
func normMAC(mac string) string {
	m := strings.ToLower(strings.TrimSpace(mac))
	m = strings.ReplaceAll(m, "-", ":")
	return m
}
