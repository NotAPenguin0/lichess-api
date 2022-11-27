use reqwest;
use oauth2;
use oauth2::reqwest::{async_http_client, Error, http_client};
use anyhow::Result;
use futures::executor::block_on;

use local_auth;
use oauth2::{RequestTokenError, TokenResponse};
use oauth2::basic::BasicErrorResponse;

/// Main entry point into the lichess API.
#[derive(Debug)]
pub struct Lichess {
    client: reqwest::Client,
}

impl Lichess {
    pub async fn new() -> anyhow::Result<Lichess> {
        let auth_port: u16 = 8080;
        let auth_uri = "http://localhost:".to_owned() + &auth_port.to_string() + "/";
        let client = oauth2::basic::BasicClient::new(
            oauth2::ClientId::new("lichess-desktop_NotAPenguin".to_string()),
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
        println!("Browse to {}", &auth_url);
        let auth_code = block_on(auth_server.listen())?;
        println!("Authentication code: {}", &auth_code);

        // After that, we can trade it for an access token
        let token_request = client
            .exchange_code(oauth2::AuthorizationCode::new(auth_code.clone()))
            .set_pkce_verifier(verifier);
        let token_result = token_request.request_async(|req| {
            //println!("Request URL: {:#?}", &req.url);
            //println!("Request headers: {:#?}", &req.headers);
            //println!("Request method: {:#?}", &req.method);
            //println!("Request body: {:#?}", String::from_utf8(req.body.clone()).unwrap());
            async_http_client(req)
        }).await;
        if let Err(e) = &token_result {
            match e {
                RequestTokenError::ServerResponse(response) => {
                    println!("Server returned error response: {:?}", response.to_string());
                }
                RequestTokenError::Request(req) => {
                    println!("Request error: {:?}", req);
                }
                RequestTokenError::Parse(err, bytes) => {
                    println!("Parse error: {:?}\n[{:?}]", err, String::from_utf8(bytes.clone()).unwrap())
                }
                RequestTokenError::Other(err) => {
                    println!("Other error: {:?}", err);
                }
            }
        }

        // REMOVE REMOVE REMOVE
        if let Some(token) = token_result.ok() {
            println!("Authentication successful: Token: {:?}", token.access_token().secret());
        }

        let http = reqwest::Client::new();
        Ok(Lichess {
            client: http
        })
    }
}