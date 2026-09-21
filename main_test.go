package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()

	server, err := newServer()
	if err != nil {
		t.Fatalf("could not create server: %v", err)
	}

	return server
}

func TestJWKS(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet,
		"/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	server.jwksHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var jwks JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != server.validKey.Kid {
		t.Error("JWKS returned incorrect kid")
	}

	if jwks.Keys[0].Kty != "RSA" {
		t.Error("expected RSA key")
	}

	if jwks.Keys[0].Alg != "RS256" {
		t.Error("expected RS256")
	}
}

func TestJWKSRejectsPost(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost,
		"/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()

	server.jwksHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestAuth(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rec := httptest.NewRecorder()

	server.authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	tokenString := strings.TrimSpace(rec.Body.String())

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return &server.validKey.PrivateKey.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("could not verify token: %v", err)
	}

	if !token.Valid {
		t.Error("expected valid token")
	}

	if token.Header["kid"] != server.validKey.Kid {
		t.Error("JWT contains incorrect kid")
	}
}

func TestExpiredAuth(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost,
		"/auth?expired=true", nil)
	rec := httptest.NewRecorder()

	server.authHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	tokenString := strings.TrimSpace(rec.Body.String())

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, err := parser.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			return &server.expiredKey.PrivateKey.PublicKey, nil
		})

	if err != nil {
		t.Fatalf("could not parse expired token: %v", err)
	}

	if token.Header["kid"] != server.expiredKey.Kid {
		t.Error("expired JWT contains incorrect kid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("could not read claims")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		t.Fatalf("could not read expiration: %v", err)
	}

	if exp.Time.After(time.Now()) {
		t.Error("expected token to already be expired")
	}
}

func TestAuthRejectsGet(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rec := httptest.NewRecorder()

	server.authHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestKeyGeneration(t *testing.T) {
	key, err := generateKey(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	if key.PrivateKey == nil {
		t.Fatal("private key should not be nil")
	}

	if key.Kid == "" {
		t.Fatal("kid should not be empty")
	}

	if key.PrivateKey.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit RSA key")
	}
}

func TestJWKConversion(t *testing.T) {
	key, err := generateKey(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	jwk := keyToJWK(key)

	if jwk.Kid != key.Kid {
		t.Error("incorrect kid")
	}

	if jwk.N == "" {
		t.Error("modulus should not be empty")
	}

	if jwk.E == "" {
		t.Error("exponent should not be empty")
	}
}

func TestRouterJWKS(t *testing.T) {
	server := setupTestServer(t)
	router := createRouter(server)

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var jwks JWKS

	if err := json.Unmarshal(rec.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("invalid JWKS response: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(jwks.Keys))
	}

	if jwks.Keys[0].Kid != server.validKey.Kid {
		t.Error("router returned incorrect key")
	}
}

func TestRouterAuth(t *testing.T) {
	server := setupTestServer(t)
	router := createRouter(server)

	req := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	if strings.TrimSpace(rec.Body.String()) == "" {
		t.Fatal("expected JWT in response")
	}
}

func TestRun(t *testing.T) {
	router, err := run()

	if err != nil {
		t.Fatalf("run returned an error: %v", err)
	}

	if router == nil {
		t.Fatal("expected router, got nil")
	}

	req := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
