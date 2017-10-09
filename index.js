const express = require('express');
const https = require('https');
const fs = require('fs');
const uuidV4 = require('uuid/v4');
const querystring = require('querystring');
const fetch = require('node-fetch');
const crypto = require("crypto");
const bigInt = require("big-integer");

const app = express();
const cookieParser = require('cookie-parser')
app.use(cookieParser());

const PORT = 3000;
const STATE_KEY = 'oauth_state';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const oauthEndPoint = (state, nonce) =>
  `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&response_type=code&scope=openid email&redirect_uri=https://localhost:${PORT}/callback&state=${state}&nonce=${nonce}`; 

const certURL = 'https://www.googleapis.com/oauth2/v3/certs';

const randomString = () => uuidV4();

// TODO: Use data store having expiration e.g. redis
const nonces = {};

app.get('/auth', (req, res) => {
  const state = randomString();
  res.cookie(STATE_KEY, state, {secure: true});
  const nonce = randomString();
  nonces[nonce] = true;
  res.redirect(oauthEndPoint(state, nonce));
});

app.get('/callback', async (req, res) => {
  const code = req.query;

  // validate state (for CSRF protection)
  const cookieState = req.cookies[STATE_KEY];
  res.clearCookie(STATE_KEY);
  if (code.state !== cookieState) {
    res.status(400).end('invalid state');
    return;
  }

  const token = await requestToken(code.code);

  // decode id_token
  const idTokenHeader = JSON.parse(
    Buffer.from(token.id_token.split('.')[0], 'base64').toString()
  );
  const idTokenPayload = JSON.parse(
    Buffer.from(token.id_token.split('.')[1], 'base64').toString()
  );

  // validate nonce (for replay attack protection)
  if (typeof nonces[idTokenPayload.nonce] === 'undefined') {
    res.status(400).end('invalid nonce');
    return;
  }
  delete nonces[idTokenPayload.nonce];
  
  res.writeHead(200);
  res.end(JSON.stringify({
    code,
    token,
    idTokenHeader,
    idTokenPayload,
  }));
});

app.get('/verify', async (req, res) => {
  const token = req.query.token;
  const idTokenHeader = JSON.parse(
    Buffer.from(token.split('.')[0], 'base64').toString()
  );
  const idTokenPayload = JSON.parse(
    Buffer.from(token.split('.')[1], 'base64').toString()
  );
  const signature = token.split('.')[2];

  const cert = await requestCert();
  let n = '';
  let e = '';
  for(let key of cert.keys) {
    if (key.kid == idTokenHeader.kid) {
      n = key.n;
      e = key.e;
      break;
    }
  }

  if (n === '') {
    res.status(400).end('token maybe expired');
    return;
  }

  const digestInfoDER = digestInfoDERFromSignature(signature, e, n);
  const hash = hashFromData(`${token.split('.')[0]}.${token.split('.')[1]}`);
  res.writeHead(200);
  res.end(JSON.stringify({
    // TODO: check digestAlgorithm
    ok: (
          idTokenPayload.iss === 'https://accounts.google.com' || 
          idTokenPayload.iss === 'accounts.google.com'
        ) &&
        idTokenPayload.aud === CLIENT_ID &&
        idTokenPayload.exp > new Date().getTime() / 1000 &&
        digestInfoDER.endsWith(hash),
    iss: idTokenPayload.iss,
    aud: idTokenPayload.aud,
    exp: idTokenPayload.exp,
    digestInfoDER,
    hash,
  }));
});

const requestToken = (code) => {
  const body = {
    code,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uri: `https://localhost:${PORT}/callback`,
    grant_type: 'authorization_code',
  }

  const tokenEndPoint = 'https://www.googleapis.com/oauth2/v4/token'

  return fetch(tokenEndPoint, { 
    method: 'POST', 
    body: querystring.stringify(body),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  }).then(
    (res) => res.json()
  );
};

const requestCert = (code) => {
  return fetch(certURL).then(
    (res) => res.json()
  );
}

const digestInfoDERFromSignature = (signature, e, n) => {
  const signatureHex = Buffer.from(signature, 'base64').toString('hex')
  const eHex  = Buffer.from(e, 'base64').toString('hex')
  const nHex = Buffer.from(n, 'base64').toString('hex')

  const signatureNum = bigInt(signatureHex, 16)
  const eNum = bigInt(eHex, 16)
  const nNum = bigInt(nHex, 16)  

  const m = signatureNum.modPow(eNum, nNum); // c^e (mod n)
  const decrypted = m.toString(16);
  const paddingRemoved = decrypted.replace(/^1f*00/g, "");
  return paddingRemoved;
}

const hashFromData = (data) => {
  return crypto.createHash('sha256').update(data).digest().toString('hex')
}

const options = {
  key:  fs.readFileSync('./server.key'),
  cert: fs.readFileSync('./oreore.crt')
};

https.createServer(options, app).listen(PORT, () => {
  console.log(`ACCESS https://localhost:${PORT}/auth`)
});
