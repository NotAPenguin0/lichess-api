mod auth;
mod error;

use futures::executor::block_on;

use reqwest;
use anyhow::Result;

use error::Error;

/// Main entry point into the lichess API.
#[derive(Debug)]
pub struct Lichess {
    client: reqwest::Client,
    token: oauth2::AccessToken
}

impl Lichess {
    /// Logs the user into their lichess account using OAuth2, and establishes a connection to the
    /// lichess API;
    pub async fn new() -> anyhow::Result<Lichess> {
        let token = auth::oauth2_login(vec!["preference:read"].as_slice()).await?;
        let http = reqwest::Client::new();
        Ok(Lichess {
            client: http,
            token
        })
    }

    /// Logs the user out of their lichess account, this will revoke the access token.
    pub async fn logout(self) -> anyhow::Result<()> {
        let response = auth::logout(&self.client, self.token).await?;
        if response.status() != 204 { // https://lichess.org/api#tag/OAuth/operation/apiTokenDelete
            return Err(anyhow::Error::new(Error::LogoutFailed));
        }
        Ok(())
    }
}