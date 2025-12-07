package providers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-pkgz/auth/v2/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailVerifyHandler_Name(t *testing.T) {
	h := &EmailVerifyHandler{ProviderName: "email"}
	assert.Equal(t, "email", h.Name())
}

func TestEmailVerifyHandler_GenerateCode(t *testing.T) {
	h := &EmailVerifyHandler{}

	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := h.generateCode()
		require.NoError(t, err)

		// Check format: XXX-XXX
		assert.Len(t, code, 7)
		assert.Equal(t, '-', rune(code[3]))

		// Check that code contains only allowed characters
		for j, ch := range code {
			if j == 3 {
				continue // skip dash
			}
			assert.Contains(t, "ABCDEFGHJKMNPQRSTUVWXYZ23456789", string(ch),
				"code contains invalid character: %c", ch)
		}

		// Check uniqueness
		assert.False(t, codes[code], "duplicate code generated: %s", code)
		codes[code] = true
	}
}

func TestEmailVerifyHandler_SendConfirmation(t *testing.T) {
	var sentAddress, sentText string
	sender := mockSender(func(address, text string) error {
		sentAddress = address
		sentText = text
		return nil
	})

	h := NewEmailVerifyHandler("email", "", sender, &mockTokenService{}, "remark42", nil, false)

	req := httptest.NewRequest(http.MethodGet, "/login?user=testuser&address=test@example.com&site=testsite", http.NoBody)
	rr := httptest.NewRecorder()

	h.LoginHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "test@example.com", sentAddress)
	assert.Contains(t, sentText, "testuser")
	assert.Contains(t, sentText, "test@example.com")

	// Check that code was stored
	h.codesMu.RLock()
	assert.Equal(t, 1, len(h.codes))
	h.codesMu.RUnlock()
}

func TestEmailVerifyHandler_SendConfirmationMissingParams(t *testing.T) {
	sender := mockSender(func(_, _ string) error {
		return nil
	})

	h := NewEmailVerifyHandler("email", "", sender, &mockTokenService{}, "remark42", nil, false)

	// Missing user
	req := httptest.NewRequest(http.MethodGet, "/login?address=test@example.com&site=testsite", http.NoBody)
	rr := httptest.NewRecorder()
	h.LoginHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Missing address
	req = httptest.NewRequest(http.MethodGet, "/login?user=testuser&site=testsite", http.NoBody)
	rr = httptest.NewRecorder()
	h.LoginHandler(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestEmailVerifyHandler_VerifyCode(t *testing.T) {
	var tokenSet bool
	sender := mockSender(func(_, _ string) error {
		return nil
	})
	tokenService := &mockTokenService{
		setFn: func(_ http.ResponseWriter, claims token.Claims) (token.Claims, error) {
			tokenSet = true
			return claims, nil
		},
	}

	h := NewEmailVerifyHandler("email", "", sender, tokenService, "remark42", nil, false)

	// First, send confirmation to get a code
	req := httptest.NewRequest(http.MethodGet, "/login?user=testuser&address=test@example.com&site=testsite", http.NoBody)
	rr := httptest.NewRecorder()
	h.LoginHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Get the generated code
	var code string
	h.codesMu.RLock()
	for c := range h.codes {
		code = c
		break
	}
	h.codesMu.RUnlock()
	require.NotEmpty(t, code)

	// Verify with the code
	req = httptest.NewRequest(http.MethodGet, "/login?token="+code, http.NoBody)
	rr = httptest.NewRecorder()
	h.LoginHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, tokenSet)

	// Code should be removed after use
	h.codesMu.RLock()
	assert.Equal(t, 0, len(h.codes))
	h.codesMu.RUnlock()
}

func TestEmailVerifyHandler_VerifyCodeCaseInsensitive(t *testing.T) {
	sender := mockSender(func(_, _ string) error {
		return nil
	})
	tokenService := &mockTokenService{
		setFn: func(_ http.ResponseWriter, claims token.Claims) (token.Claims, error) {
			return claims, nil
		},
	}

	h := NewEmailVerifyHandler("email", "", sender, tokenService, "remark42", nil, false)

	// First, send confirmation to get a code
	req := httptest.NewRequest(http.MethodGet, "/login?user=testuser&address=test@example.com&site=testsite", http.NoBody)
	rr := httptest.NewRecorder()
	h.LoginHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Get the generated code
	var code string
	h.codesMu.RLock()
	for c := range h.codes {
		code = c
		break
	}
	h.codesMu.RUnlock()

	// Verify with lowercase code
	req = httptest.NewRequest(http.MethodGet, "/login?token="+strings.ToLower(code), http.NoBody)
	rr = httptest.NewRecorder()
	h.LoginHandler(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestEmailVerifyHandler_InvalidCode(t *testing.T) {
	sender := mockSender(func(_, _ string) error {
		return nil
	})

	h := NewEmailVerifyHandler("email", "", sender, &mockTokenService{}, "remark42", nil, false)

	req := httptest.NewRequest(http.MethodGet, "/login?token=ABC-123", http.NoBody)
	rr := httptest.NewRecorder()
	h.LoginHandler(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "verification code not found")
}

func TestEmailVerifyHandler_ExpiredCode(t *testing.T) {
	sender := mockSender(func(_, _ string) error {
		return nil
	})

	h := NewEmailVerifyHandler("email", "", sender, &mockTokenService{}, "remark42", nil, false)
	h.codeTTL = 1 * time.Millisecond // Very short TTL

	// Send confirmation
	req := httptest.NewRequest(http.MethodGet, "/login?user=testuser&address=test@example.com&site=testsite", http.NoBody)
	rr := httptest.NewRecorder()
	h.LoginHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Get the generated code
	var code string
	h.codesMu.RLock()
	for c := range h.codes {
		code = c
		break
	}
	h.codesMu.RUnlock()

	// Wait for code to expire
	time.Sleep(10 * time.Millisecond)

	// Try to verify with expired code
	req = httptest.NewRequest(http.MethodGet, "/login?token="+code, http.NoBody)
	rr = httptest.NewRecorder()
	h.LoginHandler(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "expired")
}

func TestEmailVerifyHandler_CodeUsedOnce(t *testing.T) {
	sender := mockSender(func(_, _ string) error {
		return nil
	})
	tokenService := &mockTokenService{
		setFn: func(_ http.ResponseWriter, claims token.Claims) (token.Claims, error) {
			return claims, nil
		},
	}

	h := NewEmailVerifyHandler("email", "", sender, tokenService, "remark42", nil, false)

	// Send confirmation
	req := httptest.NewRequest(http.MethodGet, "/login?user=testuser&address=test@example.com&site=testsite", http.NoBody)
	rr := httptest.NewRecorder()
	h.LoginHandler(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// Get the generated code
	var code string
	h.codesMu.RLock()
	for c := range h.codes {
		code = c
		break
	}
	h.codesMu.RUnlock()

	// First verification should succeed
	req = httptest.NewRequest(http.MethodGet, "/login?token="+code, http.NoBody)
	rr = httptest.NewRecorder()
	h.LoginHandler(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Second verification should fail
	req = httptest.NewRequest(http.MethodGet, "/login?token="+code, http.NoBody)
	rr = httptest.NewRecorder()
	h.LoginHandler(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestEmailVerifyHandler_LogoutHandler(t *testing.T) {
	var resetCalled bool
	tokenService := &mockTokenService{
		resetFn: func(_ http.ResponseWriter) {
			resetCalled = true
		},
	}

	h := &EmailVerifyHandler{TokenService: tokenService}

	req := httptest.NewRequest(http.MethodGet, "/logout", http.NoBody)
	rr := httptest.NewRecorder()
	h.LogoutHandler(rr, req)

	assert.True(t, resetCalled)
}

// mockSender is a helper function to create a mock sender
type mockSender func(address, text string) error

func (m mockSender) Send(address, text string) error {
	return m(address, text)
}

// mockTokenService implements provider.VerifTokenService for testing
type mockTokenService struct {
	setFn   func(w http.ResponseWriter, claims token.Claims) (token.Claims, error)
	resetFn func(w http.ResponseWriter)
}

func (m *mockTokenService) Token(_ token.Claims) (string, error) {
	return "mock-token", nil
}

func (m *mockTokenService) Parse(_ string) (token.Claims, error) {
	return token.Claims{}, nil
}

func (m *mockTokenService) IsExpired(_ token.Claims) bool {
	return false
}

func (m *mockTokenService) Set(w http.ResponseWriter, claims token.Claims) (token.Claims, error) {
	if m.setFn != nil {
		return m.setFn(w, claims)
	}
	return claims, nil
}

func (m *mockTokenService) Reset(w http.ResponseWriter) {
	if m.resetFn != nil {
		m.resetFn(w)
	}
}
