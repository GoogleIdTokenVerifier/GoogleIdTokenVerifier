# GoogleIdTokenVerifier
To validate an Google ID Token in Golang

Usage:

```
authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"

aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"

fmt.Println(Verify(authToken, aud))
```
