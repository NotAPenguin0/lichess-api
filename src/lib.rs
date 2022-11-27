use reqwest;
use oauth2;
use oauth2::reqwest::http_client;
use anyhow::Result;
use futures::executor::block_on;

use local_auth;

/// Main entry point into the lichess API.
#[derive(Debug)]
pub struct Lichess {
    client: reqwest::Client,
}

impl Lichess {
    pub fn new() -> anyhow::Result<Lichess> {
        let auth_port: u16 = 8080;
        let auth_uri = "http://localhost:".to_owned() + &auth_port.to_string();
        let client = oauth2::basic::BasicClient::new(
            oauth2::ClientId::new("lichess-desktop".to_string()),
            None, // no client secret?
            oauth2::AuthUrl::new("https://lichess.org/oauth".to_string())?,
            Some(oauth2::TokenUrl::new("https://lichess.org/api/token".to_string())?)
        )
        .set_redirect_uri(oauth2::RedirectUrl::new(auth_uri)?);

        // generate a new PKCE challenge
        let (pkce_challenge, verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
        // generate the full authorization URL
        let (auth_url, csrf_token) = client
            .authorize_url(oauth2::CsrfToken::new_random)
            // Set desired scopes, we want read+write access for our client
            .add_scope(oauth2::Scope::new("preference:read".to_string()))
            // Set PKCE challenge
            .set_pkce_challenge(pkce_challenge)
            .url();

        let mut auth_server = block_on(local_auth::AuthListener::new(local_auth::port::Port::from(auth_port)))?;
        // User has to browse to this URL to complete the verification process
        println!("Browse to {}", auth_url);
        let auth_code = block_on(auth_server.listen())?;
        println!("Authentication code: {:?}", auth_code);

        // After that, we can trade it for an access token
        let token_result = client
            .exchange_code(oauth2::AuthorizationCode::new("Auth code obtained from URL".to_string()))
            .set_pkce_verifier(verifier)
            .request(http_client)?;

        let http = reqwest::Client::new();
        Ok(Lichess {
            client: http
        })
    }
}