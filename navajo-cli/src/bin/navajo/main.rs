use clap::Parser;
use navajo_cli::Cli;

fn main() {
    let args = Cli::parse();

    println!("{args:#?}");

    // match args.command {
    //     Command::Clone { remote } => {
    //         println!("Cloning {remote}");
    //     }
    //     Command::Diff {
    //         mut base,
    //         mut head,
    //         mut path,
    //         color,
    //     } => {
    //         if path.is_none() {
    //             path = head;
    //             head = None;
    //             if path.is_none() {
    //                 path = base;
    //                 base = None;
    //             }
    //         }
    //         let base = base
    //             .as_deref()
    //             .map(|s| s.to_str().unwrap())
    //             .unwrap_or("stage");
    //         let head = head
    //             .as_deref()
    //             .map(|s| s.to_str().unwrap())
    //             .unwrap_or("worktree");
    //         let path = path.as_deref().unwrap_or_else(|| OsStr::new(""));
    //         println!(
    //             "Diffing {}..{} {} (color={})",
    //             base,
    //             head,
    //             path.to_string_lossy(),
    //             color
    //         );
    //     }
    //     Command::Push { remote } => {
    //         println!("Pushing to {remote}");
    //     }
    //     Command::Add { path } => {
    //         println!("Adding {path:?}");
    //     }
    //     Command::Stash(stash) => {
    //         let stash_cmd = stash.command.unwrap_or(StashCommands::Push(stash.push));
    //         match stash_cmd {
    //             StashCommands::Push(push) => {
    //                 println!("Pushing {push:?}");
    //             }
    //             StashCommands::Pop { stash } => {
    //                 println!("Popping {stash:?}");
    //             }
    //             StashCommands::Apply { stash } => {
    //                 println!("Applying {stash:?}");
    //             }
    //         }
    //     }
    //     Command::External(args) => {
    //         println!("Calling out to {:?} with {:?}", &args[0], &args[1..]);
    //     }
    // }

    // Continued program logic goes here...
}
