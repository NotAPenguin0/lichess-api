mod auth;
mod error;

use std::collections::HashMap;
use reqwest;
use reqwest::Url;

use anyhow::Result;
use error::Error;

use serde::{Serialize, Deserialize};
use serde_json;

/// Main entry point into the lichess API.
#[derive(Debug)]
pub struct Lichess {
    client: reqwest::Client,
    token: oauth2::AccessToken,
    // Main lichess API endpoint
    endpoint: Url,
}

/// Rating performance for one mode.
#[derive(Deserialize, Debug)]
pub struct Performance {
    pub games: Option<u32>,
    pub rating: Option<u32>,
    /// Whether this rating is provisional
    pub prov: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct UserInfo {
    pub username: String,
    pub perfs: HashMap<String, Performance>
}

impl Lichess {
    /// Logs the user into their lichess account using OAuth2, and establishes a connection to the
    /// lichess API;
    pub async fn new() -> Result<Lichess> {
        let token = auth::oauth2_login(vec!["challenge:read", "challenge:write", "board:play"].as_slice()).await?;
        Ok(Lichess {
            client: reqwest::Client::new(),
            token,
            endpoint: Url::parse("https://lichess.org/")?
        })
    }

    /// Logs the user out of their lichess account, this will revoke the access token.
    pub async fn logout(self) -> Result<()> {
        let response = auth::logout(&self.client, self.token).await?;
        if response.status() != 204 { // https://lichess.org/api#tag/OAuth/operation/apiTokenDelete
            return Err(anyhow::Error::new(Error::LogoutFailed));
        }
        Ok(())
    }

    /// Get public information about the logged in user.
    pub async fn user_info(&self) -> Result<UserInfo> {
        Ok(Self::deserialize_response_body::<UserInfo>(self.get("api/account").await?).await?)
    }

    async fn deserialize_response_body<T>(response: reqwest::Response) -> Result<T> where T: for<'a> Deserialize<'a> {
        Ok(serde_json::from_str(&response.text().await?)?)
    }

    async fn get(&self, uri: &str) -> Result<reqwest::Response> {
        Ok(self.client.get(self.endpoint.join(uri)?)
            .bearer_auth(self.token.secret())
            .send().await?)
    }
}