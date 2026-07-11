mod auth;
mod cli;
mod commands;
mod crypto;
mod envfile;
mod fsutil;
mod keystore;
mod manifest;
mod scan;
mod ui;

use clap::Parser;

fn main() {
    ui::configure(manifest::color_choice_from_cwd());
    let cli = cli::Cli::parse();
    if let Err(err) = commands::dispatch(cli.command) {
        ui::error(format!("{err:#}"));
        std::process::exit(1);
    }
}
