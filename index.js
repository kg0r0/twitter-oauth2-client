const express = require('express');
const app = express();
const crypto = require('crypto');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const { Issuer, generators } = require('openid-client');
const config = require('./config.json');

const issuer = new Issuer({
  'authorization_endpoint': 'https://twitter.com/i/oauth2/authorize',
  'token_endpoint': 'https://api.twitter.com/2/oauth2/token'
});

const client = new issuer.Client({
  client_id: config.client_id,
  token_endpoint_auth_method: 'none'
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
    const code_verifier = generators.codeVerifier();
    const code_challenge = generators.codeChallenge(code_verifier);
    const url = client.authorizationUrl({
      redirect_uri: config.redirect_uri,
      response_type: 'code',
      scope: 'tweet.read users.read offline.access',
      state,
      code_challenge,
      code_challenge_method: 'S256',
    })
    req.session.state = state;
    req.session.code_verifier = code_verifier;
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
    const code_verifier = req.session.code_verifier;
    const params = client.callbackParams(req);
    const tokenSet = await client.oauthCallback(config.redirect_uri, params, { code_verifier, state });
    console.log('received and validated tokens %j', tokenSet);
    req.session.tokenSet = tokenSet;
    return res.redirect(req.session.originalUrl);
  })().catch(next);
});
const port = config.port || 3000;
app.listen(port, async () => {
  console.log(`Started app on port ${port}`);
});