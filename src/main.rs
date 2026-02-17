use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(about = "Patch crate dependencies using patch files")]
struct Cli {
    #[command(subcommand)]
    command: Option<PatchCommand>,
}

#[derive(Subcommand)]
enum PatchCommand {
    /// Set up a git-based editing environment and open a subshell in it
    Edit {
        /// Name of the crate to edit (must be configured in Cargo.toml metadata)
        crate_name: String,
        /// Target version to upgrade to. Downloads all intermediate versions
        /// onto an `upstream` branch so you can `git rebase` your patches forward.
        #[arg(long)]
        target: Option<String>,
    },
    /// Show the current diff between the upstream base and patched state
    Diff {
        /// Crate to diff (defaults to all configured patched crates)
        crate_name: Option<String>,
    },
    /// Extract commits on the `patched` branch as .patch files and update Cargo.toml
    Save {
        /// Name of the crate to save patches for
        crate_name: String,
    },
}

pub fn main() -> anyhow::Result<()> {
    // When invoked via `cargo patch`, cargo passes "patch" as the first arg.
    // Strip it so clap sees just the subcommands.
    let mut args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("patch") {
        args.remove(1);
    }

    let cli = Cli::parse_from(args);
    match cli.command {
        None => cargo_patch::patch(),
        Some(PatchCommand::Edit { crate_name, target }) => {
            cargo_patch::edit(&crate_name, target.as_deref())
        }
        Some(PatchCommand::Diff { crate_name }) => {
            cargo_patch::diff(crate_name.as_deref())
        }
        Some(PatchCommand::Save { crate_name }) => cargo_patch::save(&crate_name),
    }
}
