use clap::Parser;
use navajo_cli::Cli;

fn main() {
    match Cli::parse().run(std::io::stdin(), std::io::stdout()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
