# twitter-oauth2-client
## Usage
### Setup 
Set the ``client_id``, ``client_secret`` and ``redirect_uri`` in config.json.
Each value can be confirmed on the following screen of the Developer Portal.
#### client_id and client_secret
<img src="https://user-images.githubusercontent.com/33596117/146667830-260b6df0-0030-4f7e-af2d-0703e38e072d.png" width="320px">

##### redirect_uri
<img src="https://user-images.githubusercontent.com/33596117/146667853-a3bedbd9-417e-47a4-b6fa-08c627252855.png" width="320px">

### Run
  ```sh
  $ node confidential-client.js
  OR
  $ node public-client.js
  ```

## References
- https://developer.twitter.com/en/docs/twitter-api/oauth2
- https://zenn.dev/kg0r0/articles/8d787860e9b2e1
- https://www.npmjs.com/package/openid-client