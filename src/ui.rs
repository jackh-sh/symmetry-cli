//! Terminal styling: colors, symbols, and spacing.
//!
//! Color is on when stdout/stderr is a TTY and off otherwise, so piped
//! output stays clean. The manifest's `color` setting and the standard
//! `NO_COLOR` env var override that decision.

use console::{Style, StyledObject, style};

use crate::manifest::ColorChoice;

/// Apply the project's color preference. Call once at startup.
pub fn configure(choice: ColorChoice) {
    // NO_COLOR (https://no-color.org) always wins.
    if std::env::var_os("NO_COLOR").is_some() {
        set_both(false);
        return;
    }
    match choice {
        ColorChoice::Auto => {} // console auto-detects each stream
        ColorChoice::Always => set_both(true),
        ColorChoice::Never => set_both(false),
    }
}

fn set_both(enabled: bool) {
    console::set_colors_enabled(enabled);
    console::set_colors_enabled_stderr(enabled);
}

// --- line helpers -----------------------------------------------------------

/// A completed action, e.g. "✓ encrypted apps/web/.env".
pub fn ok(msg: impl std::fmt::Display) {
    println!("{} {msg}", style("✓").green().bold());
}

/// A neutral bullet line under a heading.
pub fn item(msg: impl std::fmt::Display) {
    println!("  {} {msg}", style("•").cyan());
}

/// Secondary, de-emphasized text.
pub fn detail(msg: impl std::fmt::Display) {
    println!("  {}", style(msg).dim());
}

/// A section heading with a leading blank line.
pub fn heading(msg: impl std::fmt::Display) {
    println!("\n{}", style(msg).bold());
}

/// A one-line product banner for onboarding.
pub fn banner(title: &str, tagline: &str) {
    println!("\n  {} {}", style("✦").cyan().bold(), style(title).cyan().bold());
    println!("  {}", style(tagline).dim());
}

/// A numbered step heading in a multi-step flow, e.g. "step 1/3  Files".
pub fn step(n: usize, total: usize, title: &str) {
    println!(
        "\n{}  {}",
        style(format!("step {n}/{total}")).cyan().bold(),
        style(title).bold()
    );
}

/// A green success heading marking the end of a flow.
pub fn done(msg: impl std::fmt::Display) {
    println!("\n{} {}", style("✓").green().bold(), style(msg).green().bold());
}

/// A suggested next step.
pub fn hint(msg: impl std::fmt::Display) {
    println!("{} {msg}", style("→").cyan().bold());
}

pub fn warn(msg: impl std::fmt::Display) {
    eprintln!("{} {msg}", style("warning").yellow().bold());
}

pub fn error(msg: impl std::fmt::Display) {
    eprintln!("{} {msg}", style("error").red().bold());
}

// --- inline stylers ---------------------------------------------------------

/// A file path or other identifier.
pub fn path<D>(value: D) -> StyledObject<D> {
    style(value).cyan()
}

/// An environment variable name.
pub fn var<D>(value: D) -> StyledObject<D> {
    style(value).magenta()
}

pub fn strong<D>(value: D) -> StyledObject<D> {
    style(value).bold()
}

pub fn dim<D>(value: D) -> StyledObject<D> {
    style(value).dim()
}

/// Style a file's lock state for status/show output.
pub fn state(label: &str) -> StyledObject<&str> {
    let base = Style::new();
    let styled = match label {
        "locked" => base.green(),
        "unlocked" => base.yellow(),
        "missing" => base.red().dim(),
        // "locked + plaintext on disk" and anything else: warn color
        _ => base.red(),
    };
    styled.apply_to(label)
}
