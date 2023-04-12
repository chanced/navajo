use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "xtask")]
#[command(about = "navajo tasks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    TestAll(TestAll),
}

#[derive(Debug, Parser)]
struct TestAll {
    #[arg(value_name = "VERBOSE", short = 'v', long = "verbose")]
    verbose: bool,

    /// Packege to test, defaults to workspace if not specified
    #[arg(value_name = "PACKAGE", short = 'p', long = "package")]
    package: Option<String>,
}

fn main() {}
