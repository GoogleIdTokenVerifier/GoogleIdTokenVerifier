package GoogleIdTokenVerifier

import "testing"

func TestCheckToken(t *testing.T) {
	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	actual := Verify(authToken, aud)
	var token *TokenInfo
	expected := token
	if actual != expected {
		t.Errorf("got %v\nwant %v", actual, expected)
	}
}
