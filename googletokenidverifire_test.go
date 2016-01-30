package GoogleIdTokenVerifier

import "testing"

func TestCheckToken(t *testing.T) {
	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	certs := GetCerts(GetCertsFromURL())
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	actual := VerifyGoogleIDToken(authToken, certs, aud)
	var token *TokenInfo
	expected := token
	if actual != expected {
		t.Errorf("got %v\nwant %v", actual, expected)
	}
}
