package main

import (
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setup(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.db")
	s, err := newServerAt(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	return s, path
}
func request(s *Server, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	createRouter(s).ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}
func TestSchemaAndPersistence(t *testing.T) {
	s, path := setup(t)
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count); err != nil || count < 2 {
		t.Fatalf("keys missing: %d %v", count, err)
	}
	s2, err := newServerAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.db.Close()
	var count2 int
	if err = s2.db.QueryRow(`SELECT COUNT(*) FROM keys`).Scan(&count2); err != nil || count2 != count {
		t.Fatalf("keys not persisted: %d %v", count2, err)
	}
}
func TestAuthAndJWKS(t *testing.T) {
	s, _ := setup(t)
	for _, expired := range []bool{false, true} {
		url := "/auth"
		if expired {
			url += "?expired=true"
		}
		w := request(s, "POST", url)
		if w.Code != 200 {
			t.Fatalf("auth status %d: %s", w.Code, w.Body.String())
		}
		token, _, err := new(jwt.Parser).ParseUnverified(strings.TrimSpace(w.Body.String()), jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		kid := token.Header["kid"].(string)
		var exp int64
		id, _ := strconv.ParseInt(kid, 10, 64)
		if err = s.db.QueryRow(`SELECT exp FROM keys WHERE kid=?`, id).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		if (exp <= time.Now().Unix()) != expired {
			t.Fatal("incorrect key expiration")
		}
	}
	w := request(s, "GET", "/.well-known/jwks.json")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var response JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Keys) == 0 {
		t.Fatal("missing JWKS keys")
	}
	for _, k := range response.Keys {
		if k.Kty != "RSA" || k.Alg != "RS256" || k.N == "" || k.E == "" {
			t.Fatal("bad JWK")
		}
	}
}
func TestMethodsAndErrors(t *testing.T) {
	s, _ := setup(t)
	if request(s, "GET", "/auth").Code != 405 {
		t.Fatal("auth should reject GET")
	}
	if request(s, "POST", "/.well-known/jwks.json").Code != 405 {
		t.Fatal("JWKS should reject POST")
	}
	if _, err := decodeKey(1, []byte("garbage"), 0); err == nil {
		t.Fatal("invalid PEM accepted")
	}
	if _, err := s.db.Exec(`DELETE FROM keys`); err != nil {
		t.Fatal(err)
	}
	if request(s, "POST", "/auth").Code != 500 {
		t.Fatal("missing key should fail")
	}
	if request(s, "GET", "/.well-known/jwks.json").Code != 200 {
		t.Fatal("empty JWKS should work")
	}
}
func TestDatabaseFailures(t *testing.T) {
	s, _ := setup(t)
	if _, err := saveKey(s.db, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.selectKey(false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.selectKey(true); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if request(s, "GET", "/.well-known/jwks.json").Code != 500 {
		t.Fatal("closed DB should fail")
	}
	if request(s, "POST", "/auth").Code != 500 {
		t.Fatal("closed DB auth should fail")
	}
}
func TestBadStoredKey(t *testing.T) {
	s, _ := setup(t)
	_, err := s.db.Exec(`INSERT INTO keys(key,exp) VALUES(?,?)`, []byte("bad"), time.Now().Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	if request(s, "GET", "/.well-known/jwks.json").Code != 500 {
		t.Fatal("invalid key should fail")
	}
}
func TestOpenDatabase(t *testing.T) {
	if _, err := openDatabase(filepath.Join(t.TempDir(), "missing", "x.db")); err == nil {
		t.Fatal("expected failure")
	}
	var db *sql.DB
	if db != nil {
	} // keep sql.DB type checked by compiler
}

func TestNewServerAndRun(t *testing.T) {
	s, err := newServer()
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()

	if s.db == nil {
		t.Fatal("database was not initialized")
	}

	if err := s.db.Ping(); err != nil {
		t.Fatal(err)
	}
}
func TestDatabaseErrorBranches(t *testing.T) {
	s, _ := setup(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := saveKey(s.db, time.Now().Unix()); err == nil {
		t.Fatal("saveKey should reject closed DB")
	}
	if err := ensureKeys(s.db); err == nil {
		t.Fatal("ensureKeys should reject closed DB")
	}
	if _, err := newServerAt(filepath.Join(t.TempDir(), "nonexistent", "db.sqlite")); err == nil {
		t.Fatal("newServerAt should reject invalid path")
	}
}

func TestDecodeMalformedPKCS1(t *testing.T) {
	malformed := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("not an RSA key")})
	if _, err := decodeKey(42, malformed, 0); err == nil {
		t.Fatal("invalid DER accepted")
	}
}
