mod auth;

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
        let token = auth::oauth2_login(vec!["preference:read"].as_slice()).await?;
        let http = reqwest::Client::new();
        Ok(Lichess {
            client: http
        })
    }
}