package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Entry struct {
	TS         time.Time         `json:"ts"`
	Subject    string            `json:"subject"`
	Email      string            `json:"email,omitempty"`
	Provider   string            `json:"provider,omitempty"`
	Instance   string            `json:"instance,omitempty"`
	Action     string            `json:"action"`
	Args       map[string]string `json:"args,omitempty"`
	Result     string            `json:"result"`
	HTTPStatus int               `json:"http_status,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// Logger writes audit entries to the configured backend.
type Logger interface {
	Log(Entry)
	Close() error
}

// Querier is an optional capability — only the SQLite backend implements it.
// Handlers type-assert and degrade gracefully if the active Logger does not
// also satisfy Querier.
type Querier interface {
	ListEntries(ctx context.Context, f Filter) ([]Entry, error)
}

// Filter narrows the rows returned by ListEntries. All fields are optional;
// zero values mean "no filter on this dimension". Limit defaults to 200 in
// the query layer.
type Filter struct {
	Subject  string
	Action   string
	Instance string
	Result   string
	Since    time.Time
	Until    time.Time
	Limit    int
}

// FileLogger writes one JSON object per line to a file (or stdout if path is
// empty). Used as a fallback when no SQLite db_path is configured.
type FileLogger struct {
	mu sync.Mutex
	f  *os.File
}

// NewFile opens path for append, or returns a stdout-backed logger if path
// is empty.
func NewFile(path string) (*FileLogger, error) {
	if path == "" {
		return &FileLogger{f: os.Stdout}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &FileLogger{f: f}, nil
}

func (l *FileLogger) Log(e Entry) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

func (l *FileLogger) Close() error {
	if l.f == os.Stdout {
		return nil
	}
	return l.f.Close()
}

// New returns the appropriate Logger based on which audit fields are set.
// dbPath takes precedence; if empty, falls back to filePath (JSON-lines);
// if both empty, logs to stdout. Only the SQLite backend supports query.
func New(dbPath, filePath string) (Logger, error) {
	if dbPath != "" {
		return NewSQLite(dbPath)
	}
	return NewFile(filePath)
}
