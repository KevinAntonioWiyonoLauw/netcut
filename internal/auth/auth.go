// language: Go, file: internal/auth/auth.go
// Authentication primitives: bcrypt password hashing, HS256 session tokens,
// agent credential hashing, and a login attempt limiter.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/kevinantoniowiyonolauw/netcut/internal/model"
)

// bcryptCost 12 is roughly 250ms per hash on modern hardware: slow enough to
// make offline cracking expensive, fast enough for interactive login.
const bcryptCost = 12

// ErrInvalidToken is returned for any token that fails validation.
var ErrInvalidToken = errors.New("invalid or expired token")

// HashPassword returns a bcrypt hash of pw.
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	if len(pw) > 200 {
		return "", fmt.Errorf("password must be at most 200 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword reports whether pw matches the stored bcrypt hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// Claims is the session token payload.
type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

// Issuer mints and verifies session tokens.
type Issuer struct {
	secret []byte
	ttl    time.Duration
}

// NewIssuer builds a token issuer. secret must be at least 32 bytes.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	return &Issuer{secret: []byte(secret), ttl: ttl}
}

// TTL returns the configured session lifetime.
func (i *Issuer) TTL() time.Duration { return i.ttl }

// Issue mints a signed token for u and returns it with its expiry.
func (i *Issuer) Issue(u *model.User) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(i.ttl)
	claims := Claims{
		Email: u.Email,
		Role:  string(u.Role),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			Issuer:    "netcut",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

// Parse validates a token and returns its claims. The algorithm is pinned to
// HMAC so an attacker cannot downgrade to "none" or swap in an RSA key.
func (i *Issuer) Parse(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.secret, nil
	}, jwt.WithIssuer("netcut"), jwt.WithExpirationRequired(), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// RandHex returns n cryptographically random bytes as hex.
func RandHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken returns the SHA-256 hex digest of a credential. Agent tokens are
// stored only as digests, so a database leak does not expose live credentials.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Limiter throttles repeated authentication failures per key (IP or email).
type Limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

// NewLimiter allows max failures per window before locking the key out.
func NewLimiter(max int, window time.Duration) *Limiter {
	if max <= 0 {
		max = 8
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	return &Limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

// Allow reports whether key may attempt authentication right now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	l.hits[key] = kept
	return len(kept) < l.max
}

// Fail records a failed attempt for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.hits[key] = append(l.hits[key], time.Now())
}

// Reset clears the failure history for key after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.hits, key)
}

// Remaining reports how many attempts key has left in the current window.
func (l *Limiter) Remaining(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	n := 0
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			n++
		}
	}
	if n >= l.max {
		return 0
	}
	return l.max - n
}
