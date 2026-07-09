use std::fs;
use std::path::Path;

use assert_cmd::Command;
use predicates::prelude::*;

const PASSWORD: &str = "e2e-test-password";

fn symmetry(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("symmetry").unwrap();
    cmd.current_dir(dir).env("SYMMETRY_PASSWORD", PASSWORD);
    cmd
}

fn setup_project() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::create_dir_all(root.join("apps/web")).unwrap();
    fs::create_dir_all(root.join("apps/api")).unwrap();
    fs::write(root.join(".env"), "ROOT_VAR=root\n").unwrap();
    fs::write(
        root.join("apps/web/.env"),
        "WEB_VAR=hello-web\nQUOTED=\"two words\"\n",
    )
    .unwrap();
    fs::write(root.join("apps/api/.env"), "API_VAR=hello-api\n").unwrap();
    symmetry(root).args(["init", "--password"]).assert().success();
    tmp
}

#[test]
fn init_writes_manifest_and_gitignore() {
    let tmp = setup_project();
    let root = tmp.path();

    let manifest = fs::read_to_string(root.join("symmetry.toml")).unwrap();
    assert!(manifest.contains("project_id"));
    assert!(manifest.contains("apps/web/.env"));

    let gitignore = fs::read_to_string(root.join(".gitignore")).unwrap();
    assert!(gitignore.contains(".env.*"));
    assert!(gitignore.contains("!*.enc"));

    symmetry(root)
        .args(["init", "--password"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already initialized"));
}

#[test]
fn encrypt_replaces_plaintext_and_decrypt_restores_it() {
    let tmp = setup_project();
    let root = tmp.path();
    let original = fs::read(root.join("apps/web/.env")).unwrap();

    symmetry(root).arg("encrypt").assert().success();
    assert!(!root.join("apps/web/.env").exists());
    let enc = fs::read_to_string(root.join("apps/web/.env.enc")).unwrap();
    assert!(enc.starts_with("SYMMETRY v1"));
    assert!(!enc.contains("hello-web"));

    symmetry(root).arg("decrypt").assert().success();
    assert_eq!(fs::read(root.join("apps/web/.env")).unwrap(), original);
    assert!(root.join("apps/web/.env.enc").exists());
}

#[test]
fn encrypt_keep_retains_plaintext() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).args(["encrypt", "--keep"]).assert().success();
    assert!(root.join(".env").exists());
    assert!(root.join(".env.enc").exists());
}

#[test]
fn decrypt_wrong_password_fails() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).arg("encrypt").assert().success();

    symmetry(root)
        .arg("decrypt")
        .env("SYMMETRY_PASSWORD", "not-the-password")
        .assert()
        .failure()
        .stderr(predicate::str::contains("decryption failed"));
}

#[test]
fn decrypt_refuses_to_overwrite_differing_plaintext_without_force() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).arg("encrypt").assert().success();
    fs::write(root.join(".env"), "ROOT_VAR=locally-edited\n").unwrap();

    symmetry(root)
        .args(["decrypt", ".env"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));

    symmetry(root)
        .args(["decrypt", ".env", "--force"])
        .assert()
        .success();
    assert_eq!(
        fs::read_to_string(root.join(".env")).unwrap(),
        "ROOT_VAR=root\n"
    );
}

#[test]
fn run_injects_nearest_env_file() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).arg("encrypt").assert().success();

    symmetry(&root.join("apps/web"))
        .args(["run", "--", "sh", "-c", "echo $WEB_VAR/$QUOTED/${API_VAR:-unset}"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello-web/two words/unset"));
}

#[test]
fn run_all_merges_every_env_file() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).arg("encrypt").assert().success();

    symmetry(root)
        .args(["run", "--all", "--", "sh", "-c", "echo $ROOT_VAR/$WEB_VAR/$API_VAR"])
        .assert()
        .success()
        .stdout(predicate::str::contains("root/hello-web/hello-api"));
}

#[test]
fn run_propagates_exit_code() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).arg("encrypt").assert().success();

    symmetry(root)
        .args(["run", "--", "sh", "-c", "exit 42"])
        .assert()
        .code(42);
}

#[test]
fn run_from_ambiguous_directory_needs_a_flag() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).arg("encrypt").assert().success();

    // Root .env is removed from disk but three files are in the manifest and
    // apps/ matches none of their directories except the root one.
    symmetry(&root.join("apps"))
        .args(["run", "--", "true"])
        .assert()
        .success(); // root .env matches (its dir "" contains apps/)

    symmetry(&root.join("apps"))
        .args(["run", "--file", "api/.env", "--", "sh", "-c", "echo $API_VAR"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello-api"));
}

#[test]
fn status_reports_lock_state_and_unmanaged_files() {
    let tmp = setup_project();
    let root = tmp.path();
    symmetry(root).args(["encrypt", ".env"]).assert().success();
    fs::write(root.join("apps/api/.env.staging"), "S=1\n").unwrap();

    symmetry(root)
        .arg("status")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("locked")
                .and(predicate::str::contains("unlocked"))
                .and(predicate::str::contains("Unmanaged"))
                .and(predicate::str::contains(".env.staging")),
        );
}

#[test]
fn encrypt_adds_new_files_to_manifest() {
    let tmp = setup_project();
    let root = tmp.path();
    fs::write(root.join("apps/api/.env.staging"), "S=1\n").unwrap();

    symmetry(root)
        .args(["encrypt", "apps/api/.env.staging"])
        .assert()
        .success();
    let manifest = fs::read_to_string(root.join("symmetry.toml")).unwrap();
    assert!(manifest.contains(".env.staging"));
    assert!(root.join("apps/api/.env.staging.enc").exists());
}
