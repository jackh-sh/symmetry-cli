mod decrypt;
mod encrypt;
mod init;
mod key;
mod run;
mod status;

use anyhow::Result;

use crate::cli::{Command, KeyAction};

pub fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Init { password } => init::init(password),
        Command::Encrypt { paths, keep } => encrypt::encrypt(paths, keep),
        Command::Decrypt { paths, force } => decrypt::decrypt(paths, force),
        Command::Run { file, all, command } => run::run(file, all, command),
        Command::Status => status::status(),
        Command::Key { action } => match action {
            KeyAction::Export => key::export(),
            KeyAction::Import { key } => key::import(&key),
        },
    }
}
