use lichess;
use anyhow::Result;
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    let client = lichess::Lichess::new().await?;
    let info = client.user_info().await?;
    println!("Logged in as: {:?}", info.username);
    println!("User information: {:#?}", info);

    client.logout().await?;
    Ok(())
}