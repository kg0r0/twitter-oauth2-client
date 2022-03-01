import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import { Issuer, generators, TokenSet } from 'openid-client';
import axios from 'axios';
const config: Config = require('../config.json');

interface Config {
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  client_type: 'CONFIDENTIAL' | 'PUBLIC';
}

interface UsersMeResponse {
  data: {
    id: string;
    name: string;
    username: string;
  }
}

interface RevocationResponse {
  revoked: boolean;
}

declare module 'express-session' {
  export interface SessionData {
    tokenSet: TokenSet;
    state: string;
    codeVerifier: string;
    originalUrl: string;
  }
}

const app: express.Express = express();

const issuer = new Issuer({
  issuer: 'https://twitter.com',
  authorization_endpoint: 'https://twitter.com/i/oauth2/authorize',
  token_endpoint: 'https://api.twitter.com/2/oauth2/token'
});

const confidentialClient = new issuer.Client({
  client_id: config.client_id,
  client_secret: config.client_secret,
});

const publicClient = new issuer.Client({
  client_id: config.client_id,
  token_endpoint_auth_method: 'none'
})

const client = config.client_type == 'PUBLIC' ? publicClient : confidentialClient;

app.use(session({
  name: 'session',
  secret: [crypto.randomBytes(32).toString('hex')],
  resave: true,
  saveUninitialized: true
}));

app.get('/', (req, res, next) => {
  (async () => {
    if (req.session.tokenSet) {
      const { data } = await axios.get<UsersMeResponse>('https://api.twitter.com/2/users/me',
        {
          headers: {
            Authorization: `Bearer ${req.session.tokenSet.access_token}`
          }
        });
      return res.send(`Hello ${data.data.username}!`);
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
    if (typeof req.session.originalUrl != 'string')
      throw new Error('originalUrl must be a string');
    return res.redirect(req.session.originalUrl);
  })().catch(next);
});

app.get('/refresh', (req, res, next) => {
  (async () => {
    if (!req.session || !req.session.tokenSet || !req.session.tokenSet.refresh_token) {
      return res.status(403).send('NG');
    }
    const { data } = await axios.post<TokenSet>('https://api.twitter.com/2/oauth2/token', {
      refresh_token: req.session.tokenSet.refresh_token,
      grant_type: 'refresh_token',
      client_id: config.client_id
    }, {
      auth: {
        username: config.client_id,
        password: config.client_secret
      }
    });
    console.log(data);
    req.session.tokenSet = data;
    return res.send('OK!');
  })().catch(next);
});

app.get('/revoke', (req, res, next) => {
  (async () => {
    if (!req.session.tokenSet) {
      return res.status(403).send('NG');
    }
    const { data } = await axios.post<RevocationResponse>('https://api.twitter.com/2/oauth2/revoke', {
      token: req.session.tokenSet.access_token,
      client_id: config.client_id,
      token_type_hint: 'access_token'
    }, {
      auth: {
        username: config.client_id,
        password: config.client_secret
      }
    });
    if (data.revoked) {
      req.session.destroy((err) => {
        if (err) {
          throw err;
        }
      });
    }
    return res.send(data);
  })().catch(next);
});

const port = 3000;
app.listen(port, () => {
  console.log(`Started app on port ${port}`);
});