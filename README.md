# oauth2-token-generator
Generate OAuth2 Tokens for Google APIs

Based on two-legged-oauth (2LO), needs a service account from the Google Developer Console, and associated private key in the PKCS#12 format (.p12)

```
OAuth2TokenGenerator for Google APIs. Just returns an access code so you can pipe the output into other commands

Usage:
  oauth2tokengenerator --key-file=private.p12 --client-email=example@developer.gserviceaccount.com --scopes=https://www.googleapis.com/auth/androidpublisher

Options:
  --key-file=<path>              Path to private key file (.p12 file)
  --client-email=<client-email>  Client Email
  --scopes=<scope>[,<scope>]*    Comma delimited authorization scopes
  --key-pass=<password>          Optional: private file password [default: notasecret]
  --debug                        Optional: enable verbose debug out
```
