package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchema = `
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          DATETIME NOT NULL,
  subject     TEXT NOT NULL,
  email       TEXT,
  provider    TEXT,
  instance    TEXT,
  action      TEXT NOT NULL,
  args        TEXT,
  result      TEXT NOT NULL,
  http_status INTEGER,
  error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_subject  ON audit(subject);
CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit(action);
CREATE INDEX IF NOT EXISTS idx_audit_instance ON audit(instance);
`

type SQLiteLogger struct {
	db *sql.DB
}

func NewSQLite(path string) (*SQLiteLogger, error) {
	// busy_timeout + WAL gives a single-process app sane behavior under
	// concurrent goroutine writes.
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(sqliteSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &SQLiteLogger{db: db}, nil
}

func (l *SQLiteLogger) Log(e Entry) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	var argsJSON sql.NullString
	if len(e.Args) > 0 {
		if b, err := json.Marshal(e.Args); err == nil {
			argsJSON = sql.NullString{String: string(b), Valid: true}
		}
	}
	_, _ = l.db.Exec(
		`INSERT INTO audit (ts, subject, email, provider, instance, action, args, result, http_status, error)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.UTC(), e.Subject, nullStr(e.Email), nullStr(e.Provider), nullStr(e.Instance),
		e.Action, argsJSON, e.Result, nullInt(e.HTTPStatus), nullStr(e.Error),
	)
}

func (l *SQLiteLogger) Close() error {
	return l.db.Close()
}

func (l *SQLiteLogger) ListEntries(ctx context.Context, f Filter) ([]Entry, error) {
	q := strings.Builder{}
	q.WriteString(`SELECT ts, subject, email, provider, instance, action, args, result, http_status, error FROM audit WHERE 1=1`)
	args := []any{}
	if f.Subject != "" {
		q.WriteString(` AND subject = ?`)
		args = append(args, f.Subject)
	}
	if f.Action != "" {
		q.WriteString(` AND action = ?`)
		args = append(args, f.Action)
	}
	if f.Instance != "" {
		q.WriteString(` AND instance = ?`)
		args = append(args, f.Instance)
	}
	if f.Result != "" {
		q.WriteString(` AND result = ?`)
		args = append(args, f.Result)
	}
	if !f.Since.IsZero() {
		q.WriteString(` AND ts >= ?`)
		args = append(args, f.Since.UTC())
	}
	if !f.Until.IsZero() {
		q.WriteString(` AND ts <= ?`)
		args = append(args, f.Until.UTC())
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q.WriteString(` ORDER BY ts DESC, id DESC LIMIT ?`)
	args = append(args, limit)

	rows, err := l.db.QueryContext(ctx, q.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Entry
	for rows.Next() {
		var e Entry
		var email, provider, instance, errStr, argsJSON sql.NullString
		var httpStatus sql.NullInt64
		if err := rows.Scan(&e.TS, &e.Subject, &email, &provider, &instance, &e.Action, &argsJSON, &e.Result, &httpStatus, &errStr); err != nil {
			return nil, err
		}
		e.Email = email.String
		e.Provider = provider.String
		e.Instance = instance.String
		e.Error = errStr.String
		e.HTTPStatus = int(httpStatus.Int64)
		if argsJSON.Valid && argsJSON.String != "" {
			_ = json.Unmarshal([]byte(argsJSON.String), &e.Args)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullStr(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullInt(n int) sql.NullInt64 {
	if n == 0 {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(n), Valid: true}
}
