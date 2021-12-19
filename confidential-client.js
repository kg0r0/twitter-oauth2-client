const express = require('express');
const app = express();
const crypto = require('crypto');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const { Issuer, generators } = require('openid-client');
const axios = require('axios');
const config = require('./config.json');

const issuer = new Issuer({
  authorization_endpoint: 'https://twitter.com/i/oauth2/authorize',
  token_endpoint: 'https://api.twitter.com/2/oauth2/token'
});

const client = new issuer.Client({
  client_id: config.client_id,
  client_secret: config.client_secret,
});

app.use(cookieSession({
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],
}));
app.use(cookieParser())

app.get('/', (req, res, next) => {
  (async () => {
    if (req.session.tokenSet) {
      return res.send('OK!');
    }
    const state = generators.state();
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const url = client.authorizationUrl({
      redirect_uri: config.redirect_uri,
      response_type: 'code',
      scope: 'tweet.read users.read offline.access',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })
    req.session.state = state;
    req.session.codeVerifier = codeVerifier;
    req.session.originalUrl = req.originalUrl;
    return res.redirect(url);
  })().catch(next);
});

app.get('/cb', (req, res, next) => {
  (async () => {
    if (!req.session) {
      return res.status(403).send('NG');
    }
    const state = req.session.state;
    const codeVerifier = req.session.codeVerifier;
    const params = client.callbackParams(req);
    const tokenSet = await client.oauthCallback(config.redirect_uri, params, { code_verifier: codeVerifier, state }, { exchangeBody: { client_id: config.client_id } });
    console.log('received and validated tokens %j', tokenSet);
    req.session.tokenSet = tokenSet;
    return res.redirect(req.session.originalUrl);
  })().catch(next);
});

app.get('/refresh', (req, res, next) => {
  (async () => {
    if (!req.session || !req.session.tokenSet.refresh_token) {
      return res.status(403).send('NG');
    }
    const result = await axios.post('https://api.twitter.com/2/oauth2/token', {
      refresh_token: req.session.tokenSet.refresh_token,
      grant_type: 'refresh_token',
      client_id: config.client_id
    }, {
      auth: {
        username: config.client_id,
        password: config.client_secret
      }
    });
    console.log(result.data);
    req.session.tokenSet = result.data;
    return res.send('OK!');
  })().catch(next);
});

app.get('/revoke', (req, res, next) => {
  (async () => {
    if (!req.session.tokenSet) {
      return res.status(403).send('NG');
    }
    const result = await axios.post('https://api.twitter.com/2/oauth2/revoke', {
      token: req.session.tokenSet.access_token,
      client_id: config.client_id,
      token_type_hint: 'access_token'
    });
    console.log(result.data);
    return res.send(result.data);
  })().catch(next);
});

const port = config.port || 3000;
app.listen(port, () => {
  console.log(`Started app on port ${port}`);
});