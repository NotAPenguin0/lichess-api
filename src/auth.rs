use anyhow::Result;
use oauth2::{AccessToken, PkceCodeVerifier, TokenResponse};

use local_auth;

fn create_oauth2_client(redirect_url: String) -> Result<oauth2::basic::BasicClient> {
    Ok(
        oauth2::basic::BasicClient::new(
        oauth2::ClientId::new("lichess-desktop_NotAPenguin".to_string()),
        None,
        oauth2::AuthUrl::new("https://lichess.org/oauth".to_string())?,
        Some(oauth2::TokenUrl::new("https://lichess.org/api/token".to_string())?)
        )
        .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url)?)
    )
}

/// generate an authorization URL. The user has to visit this URL and authorize access.
fn generate_auth_url(client: &oauth2::basic::BasicClient, pkce: oauth2::PkceCodeChallenge, scopes: &[&str]) -> Result<oauth2::url::Url> {
    let (auth_url, _) = client
        .authorize_url(oauth2::CsrfToken::new_random)
        .add_scopes(scopes.iter().map(|scope| oauth2::Scope::new(scope.to_string())))
        .set_pkce_challenge(pkce)
        .url();
    Ok(auth_url)
}

async fn generate_auth_code(port: u16, url: &oauth2::url::Url) -> Result<String> {
    // Create a temporary webserver that will listen to localhost:8080 for a request containing an authentication code
    // from lichess.
    let mut auth_server = local_auth::AuthListener::new(local_auth::port::Port::from(port)).await?;

    // Now we redirect the user to the authorization page to complete the verification process, and start listening for
    // requests on the webserver
    // TODO: Make this open a browser dialog/be configurable by a parameter
    println!("Browse to {:?} to authenticate", url.to_string());

    auth_server.listen().await
}

async fn exchange_token(client: &oauth2::basic::BasicClient, pkce: PkceCodeVerifier, auth_code: String) -> Result<AccessToken> {
    Ok(client
        .exchange_code(oauth2::AuthorizationCode::new(auth_code))
        .set_pkce_verifier(pkce)
        .request_async(oauth2::reqwest::async_http_client).await?.access_token().clone())
}

/// Log in to lichess using OAuth2, and return an access token that can be used in the lichess API.
pub async fn oauth2_login(scopes: &[&str]) -> Result<AccessToken> {
    let port: u16 = 8080;
    let redirect_url = "http://localhost:".to_owned() + &port.to_string() + "/";
    let client = create_oauth2_client(redirect_url)?;

    let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();
    let auth_url = generate_auth_url(&client, pkce_challenge, &scopes)?;
    let auth_code = generate_auth_code(port, &auth_url).await?;

    // We can now trade our auth code for an access token.
    // Note that these access tokens are long lived, and can probably be (safely) cached.
    exchange_token(&client, pkce_verifier, auth_code).await
}

/// Revoke token.
pub async fn logout(client: &reqwest::Client, token: AccessToken) -> anyhow::Result<reqwest::Response> {
    Ok(client.delete(reqwest::Url::parse("https://lichess.org/api/token")?)
        .bearer_auth(token.secret())
        .send().await?)
}