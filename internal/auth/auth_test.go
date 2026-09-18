// language: Go, file: internal/auth/auth_test.go
package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !CheckPassword(hash, "correct horse battery staple") {
		t.Fatal("a correct password was rejected")
	}
	if CheckPassword(hash, "wrong password") {
		t.Fatal("a wrong password was accepted")
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("the hash contains the plaintext")
	}
}

func TestPasswordLengthPolicy(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("a password shorter than 8 characters was accepted")
	}
	if _, err := HashPassword(strings.Repeat("x", 201)); err == nil {
		t.Fatal("an over-long password was accepted")
	}
}

// TestPasswordHashesAreSalted proves two hashes of the same password differ,
// which is what stops a precomputed-table attack against the user table.
func TestPasswordHashesAreSalted(t *testing.T) {
	a, err := HashPassword("same-password-twice")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("same-password-twice")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical: no salt is being applied")
	}
}

func TestTokenIssueAndParse(t *testing.T) {
	iss := NewIssuer(strings.Repeat("k", 40), time.Hour)
	u := &model.User{ID: "user-1", Email: "a@example.com", Role: model.RoleAdmin}

	tok, exp, err := iss.Issue(u)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !exp.After(time.Now()) {
		t.Fatal("expiry is not in the future")
	}

	claims, err := iss.Parse(tok)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "a@example.com" || claims.Role != "admin" {
		t.Fatalf("claims round-tripped incorrectly: %+v", claims)
	}
}

func TestTokenRejectedWithWrongSecret(t *testing.T) {
	a := NewIssuer(strings.Repeat("a", 40), time.Hour)
	b := NewIssuer(strings.Repeat("b", 40), time.Hour)

	tok, _, err := a.Issue(&model.User{ID: "u", Email: "e@x.com", Role: model.RoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Parse(tok); err == nil {
		t.Fatal("a token signed with a different secret was accepted")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	iss := NewIssuer(strings.Repeat("k", 40), -time.Minute)
	tok, _, err := iss.Issue(&model.User{ID: "u", Email: "e@x.com", Role: model.RoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Parse(tok); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

// TestAlgNoneTokenRejected covers the classic JWT downgrade: an attacker strips
// the signature and sets alg=none. The parser pins HS256, so this must fail.
func TestAlgNoneTokenRejected(t *testing.T) {
	iss := NewIssuer(strings.Repeat("k", 40), time.Hour)

	claims := Claims{
		Email: "attacker@example.com",
		Role:  string(model.RoleOwner),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "attacker",
			Issuer:    "netcut",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Parse(unsigned); err == nil {
		t.Fatal("a token using alg=none was accepted")
	}
}

// TestForeignIssuerRejected stops a token minted for another service from
// being replayed here.
func TestForeignIssuerRejected(t *testing.T) {
	secret := strings.Repeat("k", 40)
	iss := NewIssuer(secret, time.Hour)

	claims := Claims{
		Email: "e@x.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u",
			Issuer:    "some-other-service",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Parse(tok); err == nil {
		t.Fatal("a token with a foreign issuer was accepted")
	}
}

func TestTokenHashIsStableAndOneWay(t *testing.T) {
	tok := "an-agent-credential"
	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Fatal("HashToken is not deterministic")
	}
	if strings.Contains(h1, tok) {
		t.Fatal("the digest contains the credential")
	}
	if HashToken("different") == h1 {
		t.Fatal("two different credentials produced the same digest")
	}
	if len(h1) != 64 {
		t.Fatalf("digest length = %d, want 64 hex characters", len(h1))
	}
}

func TestRandHexUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		s, err := RandHex(16)
		if err != nil {
			t.Fatal(err)
		}
		if len(s) != 32 {
			t.Fatalf("RandHex(16) produced %d characters, want 32", len(s))
		}
		if seen[s] {
			t.Fatal("RandHex produced a duplicate")
		}
		seen[s] = true
	}
}

func TestLimiterLocksOutAfterMaxFails(t *testing.T) {
	l := NewLimiter(3, time.Minute)
	key := "email:a@example.com"

	for i := 0; i < 3; i++ {
		if !l.Allow(key) {
			t.Fatalf("attempt %d was blocked too early", i+1)
		}
		l.Fail(key)
	}
	if l.Allow(key) {
		t.Fatal("the limiter did not lock out after the configured number of failures")
	}
	if l.Remaining(key) != 0 {
		t.Fatalf("Remaining = %d, want 0", l.Remaining(key))
	}

	l.Reset(key)
	if !l.Allow(key) {
		t.Fatal("Reset did not clear the lockout")
	}
}

func TestLimiterExpiresOldFailures(t *testing.T) {
	l := NewLimiter(2, 50*time.Millisecond)
	key := "ip:203.0.113.9"

	l.Fail(key)
	l.Fail(key)
	if l.Allow(key) {
		t.Fatal("the limiter did not lock out")
	}
	time.Sleep(80 * time.Millisecond)
	if !l.Allow(key) {
		t.Fatal("failures did not age out of the window")
	}
}

func TestLimiterIsPerKey(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	for i := 0; i < 2; i++ {
		l.Fail("email:a@example.com")
	}
	if !l.Allow("email:b@example.com") {
		t.Fatal("one key's failures locked out an unrelated key")
	}
}
