mod common;

use cargo_test_macro::cargo_test;
use cargo_test_support::{main_file, project};

const PATCH_CONTENT: &str = r#"--- LICENSE-MIT	2020-05-20 18:44:09.709027472 +0200
+++ LICENSE-MIT	2020-05-20 18:58:46.253762666 +0200
@@ -8,9 +8,7 @@
 is furnished to do so, subject to the following
 conditions:
 
-The above copyright notice and this permission notice
-shall be included in all copies or substantial portions
-of the Software.
+PATCHED
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
"#;

fn git(dir: &std::path::Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to run git");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("invalid utf8")
}

// ========================
// edit tests
// ========================

#[allow(deprecated)]
#[cargo_test]
fn edit_creates_git_repo() {
    let manifest = r#"
        [package]
        name = "example"
        version = "0.1.0"
        authors = ["wycats@example.com"]

        [dependencies]
        serde = "=1.0.110"

        [package.metadata.patch.serde]
        patches = [
            "test.patch"
        ]
    "#;
    let p = project()
        .file("Cargo.toml", manifest)
        .file("src/main.rs", &main_file(r#""i am foo""#, &[]))
        .file("test.patch", PATCH_CONTENT)
        .build();

    p.process(common::cargo_patch_exe())
        .arg("edit")
        .arg("serde")
        .cwd(p.root())
        .run();

    let patch_dir = p.build_dir().join("patch").join("serde-1.0.110");

    // Git repo exists
    assert!(patch_dir.join(".git").exists(), "git repo should exist");

    // Has the base version tag
    let tags = git(&patch_dir, &["tag"]);
    assert!(tags.contains("v1.0.110"), "should have v1.0.110 tag");

    // Has upstream and patched branches
    let branches = git(&patch_dir, &["branch"]);
    assert!(branches.contains("upstream"), "should have upstream branch");
    assert!(branches.contains("patched"), "should have patched branch");

    // Currently on patched branch
    let current = git(&patch_dir, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert_eq!(current.trim(), "patched");

    // Existing patch was applied
    let license = std::fs::read_to_string(patch_dir.join("LICENSE-MIT"))
        .expect("should read LICENSE-MIT");
    assert!(
        license.contains("PATCHED"),
        "existing patch should be applied"
    );

    // Patch was applied as a commit (not just staged)
    let log = git(&patch_dir, &["log", "--oneline", "v1.0.110..HEAD"]);
    assert!(
        log.contains("test"),
        "should have a commit for the patch: {log}"
    );
}

#[allow(deprecated)]
#[cargo_test]
fn edit_no_existing_patches() {
    let manifest = r#"
        [package]
        name = "example"
        version = "0.1.0"
        authors = ["wycats@example.com"]

        [dependencies]
        serde = "=1.0.110"

        [package.metadata.patch.serde]
        patches = []
    "#;
    let p = project()
        .file("Cargo.toml", manifest)
        .file("src/main.rs", &main_file(r#""i am foo""#, &[]))
        .build();

    p.process(common::cargo_patch_exe())
        .arg("edit")
        .arg("serde")
        .cwd(p.root())
        .run();

    let patch_dir = p.build_dir().join("patch").join("serde-1.0.110");
    assert!(patch_dir.join(".git").exists());

    // patched branch should be at the same commit as v1.0.110
    let patched_hash = git(&patch_dir, &["rev-parse", "patched"]);
    let tag_hash = git(&patch_dir, &["rev-parse", "v1.0.110"]);
    assert_eq!(patched_hash.trim(), tag_hash.trim());
}

// ========================
// diff tests
// ========================

#[allow(deprecated)]
#[cargo_test]
fn diff_shows_changes() {
    let manifest = r#"
        [package]
        name = "example"
        version = "0.1.0"
        authors = ["wycats@example.com"]

        [dependencies]
        serde = "=1.0.110"

        [package.metadata.patch.serde]
        patches = []
    "#;
    let p = project()
        .file("Cargo.toml", manifest)
        .file("src/main.rs", &main_file(r#""i am foo""#, &[]))
        .build();

    // First set up the edit environment
    p.process(common::cargo_patch_exe())
        .arg("edit")
        .arg("serde")
        .cwd(p.root())
        .run();

    // Make a modification
    let patch_dir = p.build_dir().join("patch").join("serde-1.0.110");
    let license = patch_dir.join("LICENSE-MIT");
    std::fs::write(&license, "MODIFIED BY TEST\n").expect("write");

    // Run diff and check it shows the change
    p.process(common::cargo_patch_exe())
        .arg("diff")
        .arg("serde")
        .cwd(p.root())
        .with_stdout_contains("[..]MODIFIED BY TEST[..]")
        .run();
}

#[allow(deprecated)]
#[cargo_test]
fn diff_shows_nothing_when_clean() {
    let manifest = r#"
        [package]
        name = "example"
        version = "0.1.0"
        authors = ["wycats@example.com"]

        [dependencies]
        serde = "=1.0.110"

        [package.metadata.patch.serde]
        patches = []
    "#;
    let p = project()
        .file("Cargo.toml", manifest)
        .file("src/main.rs", &main_file(r#""i am foo""#, &[]))
        .build();

    p.process(common::cargo_patch_exe())
        .arg("edit")
        .arg("serde")
        .cwd(p.root())
        .run();

    // Diff should produce no output when nothing has changed
    p.process(common::cargo_patch_exe())
        .arg("diff")
        .arg("serde")
        .cwd(p.root())
        .with_stdout_data("")
        .run();
}

// ========================
// save tests
// ========================

#[allow(deprecated)]
#[cargo_test]
fn save_creates_per_commit_patches() {
    let manifest = r#"
        [package]
        name = "example"
        version = "0.1.0"
        authors = ["wycats@example.com"]

        [dependencies]
        serde = "=1.0.110"

        [package.metadata.patch.serde]
        patches = [
            "test.patch"
        ]
    "#;
    let p = project()
        .file("Cargo.toml", manifest)
        .file("src/main.rs", &main_file(r#""i am foo""#, &[]))
        .file("test.patch", PATCH_CONTENT)
        .build();

    // Set up edit environment (applies existing patch as first commit)
    p.process(common::cargo_patch_exe())
        .arg("edit")
        .arg("serde")
        .cwd(p.root())
        .run();

    // Make another edit and commit it
    let patch_dir = p.build_dir().join("patch").join("serde-1.0.110");
    let readme = patch_dir.join("README.md");
    std::fs::write(&readme, "SECOND EDIT\n").expect("write");
    git(&patch_dir, &["add", "-A"]);
    git(&patch_dir, &["commit", "-m", "second-edit"]);

    // Run save
    p.process(common::cargo_patch_exe())
        .arg("save")
        .arg("serde")
        .cwd(p.root())
        .run();

    // Should have created 2 patch files (one per commit)
    let patch_files: Vec<_> = std::fs::read_dir(p.root())
        .expect("read dir")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "patch")
        })
        .collect();

    // The patches go to the directory of the first configured patch path.
    // Since test.patch is at project root, the new patches should be there too.
    assert!(
        patch_files.len() >= 2,
        "should have at least 2 patch files, found {}: {:?}",
        patch_files.len(),
        patch_files.iter().map(|e| e.path()).collect::<Vec<_>>()
    );
}

#[allow(deprecated)]
#[cargo_test]
fn save_round_trip() {
    let manifest = r#"
        [package]
        name = "example"
        version = "0.1.0"
        authors = ["wycats@example.com"]

        [dependencies]
        serde = "=1.0.110"

        [package.metadata.patch.serde]
        patches = []
    "#;
    let p = project()
        .file("Cargo.toml", manifest)
        .file("src/main.rs", &main_file(r#""i am foo""#, &[]))
        .build();

    // Set up edit environment
    p.process(common::cargo_patch_exe())
        .arg("edit")
        .arg("serde")
        .cwd(p.root())
        .run();

    // Make an edit and commit
    let patch_dir = p.build_dir().join("patch").join("serde-1.0.110");
    let license = patch_dir.join("LICENSE-MIT");
    std::fs::write(&license, "ROUND TRIP TEST\n").expect("write");
    git(&patch_dir, &["add", "-A"]);
    git(&patch_dir, &["commit", "-m", "round-trip-change"]);

    // Save patches
    p.process(common::cargo_patch_exe())
        .arg("save")
        .arg("serde")
        .cwd(p.root())
        .run();

    // Wipe the patch dir
    std::fs::remove_dir_all(&patch_dir).expect("remove");

    // Run plain `cargo patch` (apply) - this should apply the saved patches
    p.process(common::cargo_patch_exe())
        .cwd(p.root())
        .run();

    // Verify the result matches our edit
    let applied = std::fs::read_to_string(&license).expect("read after apply");
    assert_eq!(
        applied, "ROUND TRIP TEST\n",
        "round-trip: applied content should match what we saved"
    );
}
