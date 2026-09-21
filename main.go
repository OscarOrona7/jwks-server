package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

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

type Server struct {
	validKey   *Key
	expiredKey *Key
}

func generateKey(expiration time.Time) (*Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kidBytes := make([]byte, 16)
	if _, err := rand.Read(kidBytes); err != nil {
		return nil, err
	}

	kid := base64.RawURLEncoding.EncodeToString(kidBytes)

	return &Key{
		PrivateKey: privateKey,
		Kid:        kid,
		ExpiresAt:  expiration,
	}, nil
}

func newServer() (*Server, error) {
	validKey, err := generateKey(time.Now().Add(1 * time.Hour))
	if err != nil {
		return nil, err
	}

	expiredKey, err := generateKey(time.Now().Add(-1 * time.Hour))
	if err != nil {
		return nil, err
	}

	return &Server{
		validKey:   validKey,
		expiredKey: expiredKey,
	}, nil
}

func base64UInt(value *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(value.Bytes())
}

func exponentToBase64(e int) string {
	eBytes := big.NewInt(int64(e)).Bytes()
	return base64.RawURLEncoding.EncodeToString(eBytes)
}

func keyToJWK(key *Key) JWK {
	publicKey := &key.PrivateKey.PublicKey

	return JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: key.Kid,
		Alg: "RS256",
		N:   base64UInt(publicKey.N),
		E:   exponentToBase64(publicKey.E),
	}
}

func (s *Server) jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	keys := []JWK{}

	if time.Now().Before(s.validKey.ExpiresAt) {
		keys = append(keys, keyToJWK(s.validKey))
	}

	response := JWKS{Keys: keys}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("could not encode JWKS: %v", err)
	}
}

func (s *Server) authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	selectedKey := s.validKey
	expiration := time.Now().Add(1 * time.Hour)

	if _, exists := r.URL.Query()["expired"]; exists {
		selectedKey = s.expiredKey
		expiration = time.Now().Add(-1 * time.Hour)
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": time.Now().Unix(),
		"exp": expiration.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = selectedKey.Kid

	signedToken, err := token.SignedString(selectedKey.PrivateKey)
	if err != nil {
		http.Error(w, "could not sign token",
			http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/jwt")
	w.WriteHeader(http.StatusOK)

	_, _ = w.Write([]byte(signedToken))
}

func createRouter(server *Server) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", server.jwksHandler)
	mux.HandleFunc("/auth", server.authHandler)

	return mux
}

func run() (*http.ServeMux, error) {
	server, err := newServer()
	if err != nil {
		return nil, err
	}

	return createRouter(server), nil
}

func main() {
	mux, err := run()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("JWKS server running at http://localhost:8080")
	fmt.Println("JWKS: http://localhost:8080/.well-known/jwks.json")
	fmt.Println("Auth: POST http://localhost:8080/auth")

	log.Fatal(http.ListenAndServe(":8080", mux))
}
