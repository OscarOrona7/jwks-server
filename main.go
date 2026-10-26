package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
)

const databaseFile = "totally_not_my_privateKeys.db"

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}
type JWKS struct {
	Keys []JWK `json:"keys"`
}
type storedKey struct {
	kid     int64
	private *rsa.PrivateKey
	exp     int64
}
type Server struct{ db *sql.DB }

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func saveKey(db *sql.DB, expiry int64) (int64, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return 0, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	result, err := db.Exec(`INSERT INTO keys(key,exp) VALUES(?,?)`, encoded, expiry)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func ensureKeys(db *sql.DB) error {
	now := time.Now().Unix()
	for _, group := range []struct {
		query  string
		expiry int64
	}{
		{`SELECT COUNT(*) FROM keys WHERE exp > ?`, now + 7200},
		{`SELECT COUNT(*) FROM keys WHERE exp <= ?`, now - 3600},
	} {
		var count int
		if err := db.QueryRow(group.query, now).Scan(&count); err != nil {
			return err
		}
		if count == 0 {
			if _, err := saveKey(db, group.expiry); err != nil {
				return err
			}
		}
	}
	return nil
}

func newServerAt(path string) (*Server, error) {
	db, err := openDatabase(path)
	if err != nil {
		return nil, err
	}
	if err = ensureKeys(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Server{db: db}, nil
}
func newServer() (*Server, error) { return newServerAt(databaseFile) }

func decodeKey(kid int64, data []byte, exp int64) (storedKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return storedKey{}, errors.New("invalid PEM")
	}
	private, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return storedKey{}, err
	}
	return storedKey{kid: kid, private: private, exp: exp}, nil
}
func (s *Server) selectKey(expired bool) (storedKey, error) {
	op, order := ">", "DESC"
	if expired {
		op, order = "<=", "DESC"
	}
	// Only hard-coded SQL fragments are used; values are parameterized.
	query := `SELECT kid,key,exp FROM keys WHERE exp ` + op + ` ? ORDER BY exp ` + order + ` LIMIT 1`
	var kid, exp int64
	var data []byte
	err := s.db.QueryRow(query, time.Now().Unix()).Scan(&kid, &data, &exp)
	if err != nil {
		return storedKey{}, err
	}
	return decodeKey(kid, data, exp)
}
func base64UInt(value *big.Int) string { return base64.RawURLEncoding.EncodeToString(value.Bytes()) }
func exponentToBase64(e int) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(e)).Bytes())
}
func keyToJWK(key storedKey) JWK {
	return JWK{Kty: "RSA", Use: "sig", Kid: fmt.Sprint(key.kid), Alg: "RS256", N: base64UInt(key.private.PublicKey.N), E: exponentToBase64(key.private.PublicKey.E)}
}
func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	rows, err := s.db.Query(`SELECT kid,key,exp FROM keys WHERE exp > ? ORDER BY kid`, time.Now().Unix())
	if err != nil {
		http.Error(w, "database error", 500)
		return
	}
	defer rows.Close()
	result := JWKS{Keys: []JWK{}}
	for rows.Next() {
		var kid, exp int64
		var data []byte
		if err = rows.Scan(&kid, &data, &exp); err != nil {
			http.Error(w, "database error", 500)
			return
		}
		key, decodeErr := decodeKey(kid, data, exp)
		if decodeErr != nil {
			http.Error(w, "invalid stored key", 500)
			return
		}
		result.Keys = append(result.Keys, keyToJWK(key))
	}
	if err = rows.Err(); err != nil {
		http.Error(w, "database error", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("JWKS encoding error: %v", err)
	}
}
func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	_, expired := r.URL.Query()["expired"]
	key, err := s.selectKey(expired)
	if err != nil {
		http.Error(w, "no usable signing key", 500)
		return
	}
	claims := jwt.MapClaims{"sub": "userABC", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	if expired {
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = fmt.Sprint(key.kid)
	signed, err := token.SignedString(key.private)
	if err != nil {
		http.Error(w, "could not sign token", 500)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	_, _ = w.Write([]byte(signed))
}
func createRouter(s *Server) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.jwksHandler)
	mux.HandleFunc("/auth", s.authHandler)
	return mux
}
func run() (*http.ServeMux, error) {
	s, err := newServer()
	if err != nil {
		return nil, err
	}
	return createRouter(s), nil
}
func main() {
	mux, err := run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("JWKS server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
