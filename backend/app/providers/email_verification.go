// Package providers implements custom authentication providers for remark42.
package providers

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // sha1 is used for ID hashing, same as original auth library
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-pkgz/auth/v2/avatar"
	"github.com/go-pkgz/auth/v2/logger"
	"github.com/go-pkgz/auth/v2/provider"
	"github.com/go-pkgz/auth/v2/token"
	"github.com/go-pkgz/rest"
	"github.com/golang-jwt/jwt/v5"
)

// EmailVerifyHandler implements email verification with short codes (XXX-XXX format)
// instead of JWT tokens for better user experience.
type EmailVerifyHandler struct {
	logger.L
	ProviderName string
	TokenService provider.VerifTokenService
	Issuer       string
	AvatarSaver  provider.AvatarSaver
	Sender       provider.Sender
	Template     string
	UseGravatar  bool

	// codeTTL is how long verification codes are valid
	codeTTL time.Duration
	// codes stores pending verification codes
	codes        map[string]codeEntry
	codesMu      sync.RWMutex
	lastCleanup  time.Time
	cleanupEvery time.Duration
}

// codeEntry stores information about a pending verification code
type codeEntry struct {
	User      string
	Address   string
	Site      string
	ExpiresAt time.Time
	SessOnly  bool
}

// NewEmailVerifyHandler creates a new email verification handler with short codes
func NewEmailVerifyHandler(name, tmpl string, sender provider.Sender, tokenService provider.VerifTokenService, issuer string, avatarSaver provider.AvatarSaver, useGravatar bool) *EmailVerifyHandler {
	return &EmailVerifyHandler{
		L:            logger.NoOp,
		ProviderName: name,
		TokenService: tokenService,
		Issuer:       issuer,
		AvatarSaver:  avatarSaver,
		Sender:       sender,
		Template:     tmpl,
		UseGravatar:  useGravatar,
		codeTTL:      30 * time.Minute,
		codes:        make(map[string]codeEntry),
		lastCleanup:  time.Now(),
		cleanupEvery: 5 * time.Minute,
	}
}

// Name returns the provider name
func (e *EmailVerifyHandler) Name() string { return e.ProviderName }

// LoginHandler handles the login flow:
// - Without token: sends confirmation email with short code
// - With token: verifies short code and creates auth token
func (e *EmailVerifyHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	tkn := r.URL.Query().Get("token")
	if tkn == "" {
		e.sendConfirmation(w, r)
		return
	}

	// Verify the short code
	e.verifyCode(w, r, tkn)
}

// AuthHandler doesn't do anything for email verification
func (e *EmailVerifyHandler) AuthHandler(_ http.ResponseWriter, _ *http.Request) {}

// LogoutHandler handles logout
func (e *EmailVerifyHandler) LogoutHandler(w http.ResponseWriter, _ *http.Request) {
	e.TokenService.Reset(w)
}

// sendConfirmation generates a short code and sends it via email
func (e *EmailVerifyHandler) sendConfirmation(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	address := r.URL.Query().Get("address")
	site := r.URL.Query().Get("site")
	sessOnly := r.URL.Query().Get("session") != "" && r.URL.Query().Get("session") != "0"

	if user == "" || address == "" {
		rest.SendErrorJSON(w, r, e.L, http.StatusBadRequest, fmt.Errorf("user and address required"), "wrong request")
		return
	}

	// Generate short code in XXX-XXX format
	code, err := e.generateCode()
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to generate verification code")
		return
	}

	// Store the code and do lazy cleanup
	e.codesMu.Lock()
	e.cleanupExpiredCodes() // lazy cleanup while we hold the lock
	e.codes[code] = codeEntry{
		User:      user,
		Address:   address,
		Site:      site,
		ExpiresAt: time.Now().Add(e.codeTTL),
		SessOnly:  sessOnly,
	}
	e.codesMu.Unlock()

	// Prepare and send email
	tmpl := msgTemplate
	if e.Template != "" {
		tmpl = e.Template
	}
	emailTmpl, err := template.New("confirm").Parse(tmpl)
	if err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't parse confirmation template")
		return
	}

	tmplData := struct {
		User    string
		Address string
		Token   string
		Site    string
	}{
		User:    trim(user),
		Address: trim(address),
		Token:   code,
		Site:    site,
	}

	var buf strings.Builder
	if err = emailTmpl.Execute(&buf, tmplData); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "can't execute confirmation template")
		return
	}

	if err := e.Sender.Send(address, buf.String()); err != nil {
		// Remove the code if email failed to send
		e.codesMu.Lock()
		delete(e.codes, code)
		e.codesMu.Unlock()
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to send confirmation")
		return
	}

	rest.RenderJSON(w, rest.JSON{"user": user, "address": address})
}

// verifyCode checks the short code and creates an auth token
func (e *EmailVerifyHandler) verifyCode(w http.ResponseWriter, r *http.Request, code string) {
	// Normalize the code (uppercase, remove extra spaces)
	code = strings.ToUpper(strings.TrimSpace(code))

	e.codesMu.Lock()
	entry, exists := e.codes[code]
	if exists {
		// Remove the code after use (one-time use)
		delete(e.codes, code)
	}
	e.codesMu.Unlock()

	if !exists {
		rest.SendErrorJSON(w, r, e.L, http.StatusForbidden, fmt.Errorf("invalid code"), "verification code not found or already used")
		return
	}

	if time.Now().After(entry.ExpiresAt) {
		rest.SendErrorJSON(w, r, e.L, http.StatusForbidden, fmt.Errorf("expired"), "verification code has expired")
		return
	}

	// Create user
	u := token.User{
		Name: entry.User,
		ID:   e.ProviderName + "_" + token.HashID(sha1.New(), entry.Address), //nolint:gosec // sha1 used for ID hashing, same as auth library
	}

	// Try to get gravatar for email
	if e.UseGravatar && strings.Contains(entry.Address, "@") {
		if picURL, err := avatar.GetGravatarURL(entry.Address); err == nil {
			u.Picture = picURL
		}
	}

	// Save avatar if available
	if e.AvatarSaver != nil && u.Picture != "" {
		avatarURL, err := e.AvatarSaver.Put(u, nil)
		if err != nil {
			e.Logf("[WARN] failed to save avatar for %s: %v", u.ID, err)
		} else {
			u.Picture = avatarURL
		}
	}

	// Create and set auth token
	claims := token.Claims{
		User: &u,
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{entry.Site},
			Issuer:   e.Issuer,
		},
		SessionOnly: entry.SessOnly,
	}

	if _, err := e.TokenService.Set(w, claims); err != nil {
		rest.SendErrorJSON(w, r, e.L, http.StatusInternalServerError, err, "failed to set auth token")
		return
	}

	rest.RenderJSON(w, rest.JSON{"user": u, "token": "authenticated"})
}

// generateCode generates a random code in XXX-XXX format (letters and numbers, no confusing chars)
func (e *EmailVerifyHandler) generateCode() (string, error) {
	// Use characters that are not easily confused
	// Excluded: 0, O, I, 1, L to avoid confusion
	const chars = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

	code := make([]byte, 7) // XXX-XXX = 7 characters including dash
	randomBytes := make([]byte, 6)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := 0; i < 3; i++ {
		code[i] = chars[int(randomBytes[i])%len(chars)]
	}
	code[3] = '-'
	for i := 4; i < 7; i++ {
		code[i] = chars[int(randomBytes[i-1])%len(chars)]
	}

	return string(code), nil
}

// cleanupExpiredCodes removes expired codes from memory if enough time has passed
// This is called lazily during operations rather than in a background goroutine
func (e *EmailVerifyHandler) cleanupExpiredCodes() {
	now := time.Now()
	if now.Sub(e.lastCleanup) < e.cleanupEvery {
		return
	}

	e.lastCleanup = now
	for code, entry := range e.codes {
		if now.After(entry.ExpiresAt) {
			delete(e.codes, code)
		}
	}
}

// trim removes newlines and trims whitespace, limiting to 128 chars
func trim(inp string) string {
	res := strings.ReplaceAll(inp, "\n", "")
	res = strings.TrimSpace(res)
	if len(res) > 128 {
		return res[:128]
	}
	return res
}

var msgTemplate = `
Confirmation for {{.User}} {{.Address}}, site {{.Site}}

Your verification code: {{.Token}}
`
