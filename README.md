# OpenID Connect Test Client

This is test implement so NOT recommended use in production.

## Usage

Get CLIENT_ID and CLIENT_SECRET by [Google API Console](https://console.developers.google.com/).

```
$ sh genTestCert.sh
$ CLIENT_ID=*** CLIENT_SECRET=*** node index.js
```

### Auth

https://localhost:3000/auth 

```
{
  "code": {
    "state": "*****",
    "code": "*****",
    "authuser": "0",
    "session_state": "*****",
    "prompt": "none"
  },
  "token": {
    "access_token": "*****.*****.*****"
  },
  "id_token_header": {
    "alg": "RS256",
    "kid": "5b0924f6f83c719514987954cf66683b370677d4"
  },
  "id_token_payload": {
    "azp": "*****",
    "aud": "*****",
    "sub": "*****",
    "email": "****@gmail.com",
    "email_verified": true,
    "at_hash": "*****",
    "nonce": "*****",
    "iss": "https://accounts.google.com",
    "iat": 1506613038,
    "exp": 1506616638
  },
  "id_token_verify_signature": "*****"
}
```

### Verify ID Token

https://localhost:3000/verify?token=****

```
{
  "ok": true,
  "digestInfoDER": "*****",
  "hash": "******"
}
```

## Article

[OpenID ConnectのIDトークンの内容と検証](https://www.sambaiz.net/article/136/)