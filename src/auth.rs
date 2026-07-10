//! OS user verification for strict mode.
//!
//! Supported on macOS (Touch ID / Apple Watch / account password) and
//! Windows (Windows Hello biometrics / PIN). Linux is fail-closed for now:
//! the upstream polkit backend in robius-authentication is incomplete.

use anyhow::Result;

/// Whether strict mode can be enforced on this platform. Checked before
/// letting the user turn strict mode on, so they can't lock themselves out.
pub fn supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "windows"))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn verify_user(reason: &str) -> Result<()> {
    use anyhow::{Context as _, bail};
    use robius_authentication::{
        AndroidText, BiometricStrength, Context, Policy, PolicyBuilder, Text, WindowsText,
    };

    let policy: Policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(true)
        .watch(true)
        .build()
        .context(
            "strict mode is enabled but no user authentication method \
             (biometrics or account password) is available on this system",
        )?;
    let text = Text {
        android: AndroidText {
            title: "Symmetry",
            subtitle: None,
            description: Some(reason),
        },
        apple: reason,
        windows: WindowsText::new("Symmetry", reason)
            .expect("static prompt strings are valid"),
    };
    if let Err(err) = Context::new(()).blocking_authenticate(text, &policy) {
        bail!("user verification failed or was cancelled ({err:?})");
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub fn verify_user(_reason: &str) -> Result<()> {
    anyhow::bail!(
        "this key is in strict mode, which is not supported on this platform yet; \
         re-import the key without --strict on a supported machine"
    );
}
