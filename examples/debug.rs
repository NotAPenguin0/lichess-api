use lichess;
use anyhow::Result;
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    let client = lichess::Lichess::new().await?;
    client.logout().await?;

    Ok(())
}