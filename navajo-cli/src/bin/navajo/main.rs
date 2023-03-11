use clap::Parser;
use navajo_cli::Cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    Cli::parse()
        .execute(tokio::io::stdin(), tokio::io::stdout())
        .await
}
