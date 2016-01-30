# GoogleIdTokenVerifier
To validate an Google ID Token in Golang

Usage:

```
authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"

certs := getCerts(getCertsFromURL())

aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"

fmt.Println(verifyGoogleIDToken(authToken, certs, aud))
```
