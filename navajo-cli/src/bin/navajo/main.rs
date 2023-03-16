use clap::Parser;
use navajo_cli::Cli;

#[tokio::main]
async fn main() {
    match Cli::parse()
        .run(tokio::io::stdin(), tokio::io::stdout())
        .await
    {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
