package traffic

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"unicode/utf8"
)

// indexDB keeps the shared query code in one place. SQLite remains a reference
// backend for old-file migrations and benchmarks; production uses PostgreSQL.
type indexDB struct {
	*sql.DB
	postgres bool
}

func bindIndexSQL(query string, postgres bool) string {
	if !postgres {
		return query
	}
	// All statements here are application-owned SQL, never user input. Respect
	// quoted literals while rebinding placeholders (including ESCAPE '\').
	var out strings.Builder
	quoted := false
	parameter := 0
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if ch == '\'' {
			if quoted && i+1 < len(query) && query[i+1] == '\'' {
				out.WriteString("''")
				i++
				continue
			}
			quoted = !quoted
		}
		if ch == '?' && !quoted {
			parameter++
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(parameter))
		} else {
			out.WriteByte(ch)
		}
	}
	return out.String()
}

// Metadata keeps SQLite's case-insensitive matching on PostgreSQL. Apply only
// to application-owned condition templates, never parameters or search SQL:
// folded search documents deliberately use case-sensitive LIKE.
func (t *Traffic) metadataLike(condition string) string {
	if t.db.postgres {
		return strings.ReplaceAll(condition, " LIKE ", " ILIKE ")
	}
	return condition
}

func (d *indexDB) Exec(query string, args ...any) (sql.Result, error) {
	return d.DB.Exec(bindIndexSQL(query, d.postgres), args...)
}

func (d *indexDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, bindIndexSQL(query, d.postgres), args...)
}

func (d *indexDB) Query(query string, args ...any) (*sql.Rows, error) {
	return d.DB.Query(bindIndexSQL(query, d.postgres), args...)
}

func (d *indexDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, bindIndexSQL(query, d.postgres), args...)
}

func (d *indexDB) QueryRow(query string, args ...any) *sql.Row {
	return d.DB.QueryRow(bindIndexSQL(query, d.postgres), args...)
}

func (d *indexDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, bindIndexSQL(query, d.postgres), args...)
}

func (d *indexDB) Begin() (*indexTx, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &indexTx{Tx: tx, postgres: d.postgres}, nil
}

func (d *indexDB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*indexTx, error) {
	tx, err := d.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &indexTx{Tx: tx, postgres: d.postgres}, nil
}

type indexTx struct {
	*sql.Tx
	postgres bool
}

func (tx *indexTx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.Tx.Exec(bindIndexSQL(query, tx.postgres), args...)
}

func (tx *indexTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.Tx.ExecContext(ctx, bindIndexSQL(query, tx.postgres), args...)
}

func (tx *indexTx) QueryRow(query string, args ...any) *sql.Row {
	return tx.Tx.QueryRow(bindIndexSQL(query, tx.postgres), args...)
}

func (tx *indexTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return tx.Tx.QueryRowContext(ctx, bindIndexSQL(query, tx.postgres), args...)
}

func literalLike(term string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(term) + "%"
}

// cleanIndexText normalizes a derived search document in a single pass so
// PostgreSQL text columns never receive NUL bytes or invalid UTF-8 sequences.
// Clean UTF-8 inputs without NUL bytes return with zero allocations.
func cleanIndexText(s string) string {
	i := 0
	for i < len(s) {
		c := s[i]
		if c == 0 {
			break
		}
		if c < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			break
		}
		i += size
	}
	if i == len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString(s[:i])
	inInvalid := false
	for i < len(s) {
		c := s[i]
		if c == 0 {
			inInvalid = false
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		if c < utf8.RuneSelf {
			inInvalid = false
			b.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if !inInvalid {
				b.WriteRune(utf8.RuneError)
				inInvalid = true
			}
			i++
			continue
		}
		inInvalid = false
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// PostgreSQL text cannot hold NUL or invalid UTF-8. Only the derived search
// document is normalized; original headers and bodies are stored as bytea.
func searchText(s string) string {
	return cleanIndexText(s)
}

func (t *Traffic) headerValue(header string) any {
	if t.db.postgres {
		return []byte(header)
	}
	return header
}
