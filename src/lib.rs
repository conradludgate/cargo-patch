//! `Cargo-Patch` is a Cargo Subcommand which allows
//! patching dependencies using patch files.
//!
//! # Installation
//!
//! Simply run:
//!
//! ```sh
//! cargo install cargo-patch
//! ```
//!
//! # Usage
//!
//! To patch a dependency one has to add the following
//! to `Cargo.toml`:
//!
//! ```toml
//! [package.metadata.patch.serde]
//! version = "1.0"
//! patches = [
//!     "test.patch"
//! ]
//! ```
//!
//! It specifies which dependency to patch (in this case
//! serde) and one or more patchfiles to apply. Running:
//!
//! ```sh
//! cargo patch
//! ```
//!
//! will download the serde package specified in the
//! dependency section to the `target/patch` folder
//! and apply the given patches. To use the patched
//! version one has to override the dependency using
//! `replace` like this
//!
//! ```toml
//! [patch.crates-io]
//! serde = { path = './target/patch/serde-1.0.110' }
//! ```
//!
//! # Developing patches
//!
//! The `edit`, `diff`, and `save` subcommands provide a git-based workflow
//! for creating and maintaining patches.
//!
//! ```sh
//! # Opens a subshell in the patch directory with git branches set up
//! cargo patch edit serde
//!
//! # Inside the subshell: edit files, commit changes
//! git add -A && git commit -m "my-change"
//! exit
//!
//! # Preview the diff
//! cargo patch diff serde
//!
//! # Extract commits as .patch files and update Cargo.toml
//! cargo patch save serde
//! ```
//!
//! ## Version upgrades
//!
//! To upgrade a patched crate to a newer version, use `--target` to
//! download intermediate versions onto an `upstream` branch, then rebase:
//!
//! ```sh
//! # Drops into a subshell; rebase instructions are printed
//! cargo patch edit serde --target 1.0.200
//!
//! # Inside the subshell:
//! git rebase --onto v1.0.200 v1.0.110 patched
//! # resolve any conflicts, then exit
//! exit
//!
//! cargo patch save serde
//! ```
//!
//! # Patch format
//!
//! You can either use [diff](http://man7.org/linux/man-pages/man1/diff.1.html) or
//! [git](https://linux.die.net/man/1/git) to create patch files. Important is that
//! file paths are relative and inside the dependency.
//!
//! # Limitations
//!
//! Its only possible to patch dependencies of binary crates as it is not possible
//! for a subcommand to intercept the build process.
//!

#![warn(clippy::all, clippy::nursery)]
#![warn(nonstandard_style, rust_2018_idioms)]

use anyhow::{anyhow, Context, Result};
use cargo::{
    core::{
        package::{Package, PackageSet},
        registry::PackageRegistry,
        resolver::{features::CliFeatures, HasDevUnits},
        shell::Verbosity,
        PackageId, Resolve, Workspace,
    },
    ops::{get_resolved_packages, load_pkg_lockfile, resolve_with_previous},
    util::important_paths::find_root_manifest_for_wd,
    GlobalContext,
};

use cargo::sources::SourceConfigMap;
use cargo::util::cache_lock::CacheLockMode::DownloadExclusive;
use fs_extra::dir::{copy, CopyOptions};
use patch::{Line, Patch};
use semver::VersionReq;
use std::fmt::{Display, Formatter};
use std::process::Command;
use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use toml::Value;

// ========================
// Types
// ========================

#[derive(Debug, Clone, Default)]
enum PatchSource {
    #[default]
    Default,
    GithubPrDiff,
}

#[derive(Debug, Clone)]
struct PatchItem<'a> {
    path: &'a Path,
    source: PatchSource,
}

#[derive(Debug, Clone)]
struct PatchEntry<'a> {
    name: &'a str,
    version: Option<VersionReq>,
    patches: Vec<PatchItem<'a>>,
}

/// Lightweight patch config parsed directly from Cargo.toml metadata,
/// without needing a full cargo workspace resolution.
#[derive(Debug, Clone)]
struct PatchConfig {
    name: String,
    version: semver::Version,
    patch_paths: Vec<PathBuf>,
}

#[derive(Debug)]
struct PatchFailed {
    line: u64,
    file: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
enum PatchType {
    Modify,
    Create,
    Delete,
}

impl PatchSource {
    fn from_str(s: &str) -> Self {
        match s {
            "Default" => Self::Default,
            "GithubPrDiff" => Self::GithubPrDiff,
            &_ => {
                eprintln!("Unknown patch source: {s}");
                Self::Default
            }
        }
    }
}

impl std::error::Error for PatchFailed {}

impl Display for PatchFailed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to apply patch to {} on line {}",
            self.file.display(),
            self.line + 1
        )
    }
}

// ========================
// Git helper
// ========================

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn git_stdout(dir: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .with_context(|| format!("failed to run git {}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("git {} failed", args.join(" "));
    }
    Ok(())
}

/// Returns `true` if auto-save should proceed (shell exited 0 or was skipped for tests).
fn spawn_subshell(dir: &Path) -> Result<bool> {
    if std::env::var_os("CARGO_PATCH_NO_SHELL").is_some() {
        return Ok(false);
    }
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    let status = Command::new(&shell)
        .current_dir(dir)
        .status()
        .with_context(|| format!("failed to spawn {shell}"))?;
    Ok(status.success())
}

/// Strip a leading `NNNN-` numeric prefix from a patch-derived commit message.
fn strip_patch_number_prefix(name: &str) -> &str {
    let mut s = name;
    while s.len() > 5
        && s.as_bytes()[..4].iter().all(|b| b.is_ascii_digit())
        && s.as_bytes()[4] == b'-'
    {
        s = &s[5..];
    }
    s
}

// ========================
// Workspace and metadata helpers
// ========================

fn clear_patch_folder() -> Result<()> {
    match fs::remove_dir_all("target/patch") {
        Ok(_) => Ok(()),
        Err(err) => match err.kind() {
            ErrorKind::NotFound => Ok(()),
            _ => Err(err.into()),
        },
    }
}

fn setup_gctx() -> Result<GlobalContext> {
    let gctx = GlobalContext::default()?;
    gctx.shell().set_verbosity(Verbosity::Quiet);
    Ok(gctx)
}

fn find_cargo_toml(path: &Path) -> Result<PathBuf> {
    let path = fs::canonicalize(path)?;
    find_root_manifest_for_wd(&path)
}

fn fetch_workspace<'gctx>(
    gctx: &'gctx GlobalContext,
    path: &Path,
) -> Result<Workspace<'gctx>> {
    Workspace::new(path, gctx)
}

fn resolve_ws<'a>(ws: &Workspace<'a>) -> Result<(PackageSet<'a>, Resolve)> {
    let scm = SourceConfigMap::new(ws.gctx())?;
    let mut registry = PackageRegistry::new_with_source_config(ws.gctx(), scm)?;

    registry.lock_patches();
    let resolve = {
        let prev = load_pkg_lockfile(ws)?;
        let resolve: Resolve = resolve_with_previous(
            &mut registry,
            ws,
            &CliFeatures::new_all(true),
            HasDevUnits::No,
            prev.as_ref(),
            None,
            &[],
            false,
        )?;
        resolve
    };
    let packages = get_resolved_packages(&resolve, registry)?;
    Ok((packages, resolve))
}

fn get_patches(
    custom_metadata: &Value,
) -> impl Iterator<Item = PatchEntry<'_>> + '_ {
    custom_metadata
        .as_table()
        .and_then(|table| table.get("patch"))
        .into_iter()
        .flat_map(|patch| patch.as_table().into_iter())
        .flat_map(|table| {
            table
                .into_iter()
                .filter_map(|(k, v)| parse_patch_entry(k, v))
        })
}

fn parse_patch_entry<'a>(name: &'a str, entry: &'a Value) -> Option<PatchEntry<'a>> {
    let entry = entry.as_table().or_else(|| {
        eprintln!("Entry {name} must contain a table.");
        None
    })?;

    let version = entry.get("version").and_then(|version| {
        let value = version.as_str().and_then(|s| VersionReq::parse(s).ok());
        if value.is_none() {
            eprintln!("Version must be a value semver string: {version}");
        }
        value
    });

    let patches = entry
        .get("patches")
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|patches| {
            patches.iter().flat_map(|patch| {
                let item = if patch.is_str() {
                    Some((patch.as_str(), Default::default()))
                } else {
                    patch.as_table().map(
                        |it| (
                            it.get("path").and_then(Value::as_str),
                            it.get("source").and_then(Value::as_str)
                              .map_or_else(Default::default, PatchSource::from_str)
                        ))
                };

                let (path, source) = if let Some(item) = item {item } else {
                    eprintln!("Patch Entry must be a string or a table with path and source: {patch}");
                    return None;
                };

                let path = path.map(Path::new);
                let path = if let Some(path) = path {
                    path
                } else {
                    eprintln!("Patch Entry must be a string or a table with path and source: {patch}");
                    return None;
                };

                Some(PatchItem {
                    path,
                    source,
                })
            })
        })
        .collect();

    Some(PatchEntry {
        name,
        version,
        patches,
    })
}

fn get_id(
    name: &str,
    version: &Option<VersionReq>,
    resolve: &Resolve,
) -> Option<PackageId> {
    let mut matched_dep = None;
    for dep in resolve.iter() {
        if dep.name().as_str() == name
            && version
                .as_ref()
                .is_none_or(|ver| ver.matches(dep.version()))
        {
            if matched_dep.is_none() {
                matched_dep = Some(dep);
            } else {
                eprintln!("There are multiple versions of {name} available. Try specifying a version.");
            }
        }
    }
    if matched_dep.is_none() {
        eprintln!("Unable to find package {name} in dependencies");
    }
    matched_dep
}

fn find_patch_dir(crate_name: &str, version: &semver::Version) -> PathBuf {
    PathBuf::from(format!("target/patch/{crate_name}-{version}"))
}

/// Read patch configs directly from Cargo.toml without cargo workspace resolution.
fn read_patch_configs() -> Result<Vec<PatchConfig>> {
    let cargo_toml_path = find_cargo_toml(&PathBuf::from("."))?;
    let content = fs::read_to_string(&cargo_toml_path)?;
    let doc: toml::Table = content.parse().context("Failed to parse Cargo.toml")?;

    let mut configs = Vec::new();
    for scope in &["workspace", "package"] {
        let patches = doc
            .get(*scope)
            .and_then(|v| v.get("metadata"))
            .and_then(|v| v.get("patch"))
            .and_then(|v| v.as_table());
        if let Some(patches) = patches {
            for (name, entry) in patches {
                if let Some(config) = parse_patch_config(name, entry) {
                    configs.push(config);
                }
            }
        }
    }
    Ok(configs)
}

fn parse_patch_config(name: &str, entry: &Value) -> Option<PatchConfig> {
    let table = entry.as_table()?;

    let version_str = table.get("version")?.as_str()?;
    // Strip leading "=" if present (e.g. "=1.0.110" → "1.0.110")
    let version_str = version_str.strip_prefix('=').unwrap_or(version_str);
    let version = semver::Version::parse(version_str).ok()?;

    let patch_paths = table
        .get("patches")
        .and_then(Value::as_array)
        .into_iter()
        .flat_map(|arr| {
            arr.iter().filter_map(|v| {
                let path_str = if v.is_str() {
                    v.as_str()
                } else {
                    v.as_table()
                        .and_then(|t| t.get("path"))
                        .and_then(Value::as_str)
                };
                path_str.map(PathBuf::from)
            })
        })
        .collect();

    Some(PatchConfig {
        name: name.to_string(),
        version,
        patch_paths,
    })
}

fn read_patch_config_for(crate_name: &str) -> Result<PatchConfig> {
    read_patch_configs()?
        .into_iter()
        .find(|c| c.name == crate_name)
        .ok_or_else(|| {
            anyhow!("No patch entry found for '{crate_name}' in Cargo.toml metadata")
        })
}

// ========================
// Package copying
// ========================

fn copy_package(pkg: &Package) -> Result<PathBuf> {
    let patch_dir = Path::new("target/patch/");
    fs::create_dir_all(patch_dir)?;
    let options = CopyOptions::new();
    let _ = copy(pkg.root(), patch_dir, &options)?;
    if let Some(name) = pkg.root().file_name() {
        Ok(patch_dir.join(name).canonicalize()?)
    } else {
        Err(anyhow!("Dependency Folder does not have a name"))
    }
}

// ========================
// Crate downloading (for --target)
// ========================

fn download_crate_archive(name: &str, version: &semver::Version) -> Result<Vec<u8>> {
    let url = format!("https://crates.io/api/v1/crates/{name}/{version}/download");
    let mut easy = curl::easy::Easy::new();
    easy.url(&url)?;
    easy.follow_location(true)?;
    easy.useragent("cargo-patch")?;
    let mut data = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|d| {
            data.extend_from_slice(d);
            Ok(d.len())
        })?;
        transfer.perform()?;
    }
    Ok(data)
}

fn extract_crate_to(archive_data: &[u8], dest: &Path) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(archive_data);
    let mut archive = tar::Archive::new(decoder);

    let temp_dir = dest.with_extension("_extract_tmp");
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir)?;
    }
    fs::create_dir_all(&temp_dir)?;

    archive.unpack(&temp_dir)?;

    // The archive contains a top-level directory like "serde-1.0.110/"
    // Find it and move its contents to dest
    let mut entries = fs::read_dir(&temp_dir)?;
    let top_dir = entries
        .next()
        .ok_or_else(|| anyhow!("Empty crate archive"))??
        .path();

    // Remove old contents of dest (except .git)
    if dest.exists() {
        for entry in fs::read_dir(dest)? {
            let entry = entry?;
            let name = entry.file_name();
            if name != ".git" {
                let path = entry.path();
                if path.is_dir() {
                    fs::remove_dir_all(&path)?;
                } else {
                    fs::remove_file(&path)?;
                }
            }
        }
    } else {
        fs::create_dir_all(dest)?;
    }

    // Copy contents from extracted dir to dest
    for entry in fs::read_dir(&top_dir)? {
        let entry = entry?;
        let src = entry.path();
        let dst = dest.join(entry.file_name());
        if src.is_dir() {
            let options = CopyOptions::new();
            copy(&src, dest, &options)?;
        } else {
            fs::copy(&src, &dst)?;
        }
    }

    fs::remove_dir_all(&temp_dir)?;
    Ok(())
}

fn query_crate_versions(
    name: &str,
    from: &semver::Version,
    to: &semver::Version,
) -> Result<Vec<semver::Version>> {
    let url = format!("https://crates.io/api/v1/crates/{name}/versions");
    let mut easy = curl::easy::Easy::new();
    easy.url(&url)?;
    easy.follow_location(true)?;
    easy.useragent("cargo-patch")?;
    let mut data = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|d| {
            data.extend_from_slice(d);
            Ok(d.len())
        })?;
        transfer.perform()?;
    }

    // Parse the JSON response to extract version numbers
    // The response has: { "versions": [ { "num": "1.0.0", "yanked": false, ... }, ... ] }
    let json: serde_json::Value = serde_json::from_slice(&data)
        .context("Failed to parse crates.io response")?;

    let versions = json["versions"]
        .as_array()
        .ok_or_else(|| anyhow!("Unexpected crates.io response format"))?;

    let mut result: Vec<semver::Version> = versions
        .iter()
        .filter_map(|v| {
            let yanked = v["yanked"].as_bool().unwrap_or(true);
            if yanked {
                return None;
            }
            let num = v["num"].as_str()?;
            let ver = semver::Version::parse(num).ok()?;
            if ver > *from && ver <= *to {
                Some(ver)
            } else {
                None
            }
        })
        .collect();

    result.sort();
    Ok(result)
}

// ========================
// Patch application
// ========================

fn do_patch(
    diff: Patch<'_>,
    old_path: Option<PathBuf>,
    new_path: Option<PathBuf>,
) -> Result<PatchType> {
    // delete
    if new_path.is_none() {
        if let Some(old) = old_path {
            fs::remove_file(old)?;
            return Ok(PatchType::Delete);
        }
        return Err(anyhow!("Both old and new file are all empty."));
    }
    let new_path = new_path.unwrap();

    let (old_data, patch_type) = if let Some(old) = old_path {
        // modify
        (fs::read_to_string(old)?, PatchType::Modify)
    } else {
        // create
        ("".to_string(), PatchType::Create)
    };

    let data =
        apply_patch(diff, &old_data).map_err(|line| PatchFailed {
            file: PathBuf::from(new_path.to_owned().file_name().map_or_else(
                || "".to_string(),
                |it| it.to_string_lossy().to_string(),
            )),
            line,
        })?;

    if patch_type == PatchType::Create {
        if let Some(parent) = new_path.parent() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(&new_path, data)?;

    Ok(patch_type)
}

fn cleanup_package_dir(_path: &Path, _package: &Package) -> Result<()> {
    // delete any unused files?
    Ok(())
}

fn apply_patches<'a>(
    name: &str,
    patches: impl Iterator<Item = PatchItem<'a>> + 'a,
    path: &Path,
) -> Result<()> {
    for PatchItem {
        path: patch,
        source,
    } in patches
    {
        let data = read_to_string(patch)?;
        let patches = Patch::from_multiple(&data)
            .map_err(|_| anyhow!("Unable to parse patch file"))?;
        for patch in patches {
            fn check_path<P: AsRef<Path>>(
                base: &Path,
                path: P,
                loc: &str,
            ) -> Result<PathBuf> {
                let path = base.join(path);
                let canonicalize_result = path.canonicalize();

                if canonicalize_result.is_err()
                    && path.to_string_lossy().contains("..")
                {
                    return Err(anyhow!(
                        "Failed to canonicalize path and the path has .. in it. ({loc})",
                    ));
                } else if canonicalize_result.is_err() {
                    return Ok(path);
                }

                if canonicalize_result?.strip_prefix(base).is_err() {
                    return Err(anyhow!(
                        "Patch file tried to escape dependency folder ({loc})",
                    ));
                }

                Ok(path)
            }

            let (old_path, new_path) = match source {
                PatchSource::Default => {
                    (patch.old.path.as_ref(), patch.new.path.as_ref())
                }
                PatchSource::GithubPrDiff => (
                    patch
                        .old
                        .path
                        .strip_prefix("a/")
                        .unwrap_or_else(|| patch.old.path.as_ref()),
                    patch
                        .new
                        .path
                        .strip_prefix("b/")
                        .unwrap_or_else(|| patch.new.path.as_ref()),
                ),
            };

            let loc = format!("{name}: {old_path} -> {new_path}");
            let loc_simple = format!("{name}: {old_path}");

            let new_file_path = check_path(path, new_path, &loc);
            let old_file_path = check_path(path, old_path, &loc);

            let new_file_path = if patch.new.path == "/dev/null" {
                None
            } else {
                Some(new_file_path?)
            };
            let old_file_path = if patch.old.path == "/dev/null" {
                None
            } else {
                Some(old_file_path?)
            };

            let patch_type = do_patch(patch, old_file_path, new_file_path)?;

            let loc = match patch_type {
                PatchType::Modify => loc_simple,
                PatchType::Create | PatchType::Delete => loc,
            };
            println!("Patched {loc}");
        }
    }
    Ok(())
}

/// Apply a patch to the given text.
/// If the apply fails (i.e. due to mismatch in context lines), returns an Err with the line number
/// it failed on (0-based).
#[allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]
fn apply_patch(diff: Patch<'_>, old: &str) -> Result<String, u64> {
    let old_lines = old.lines().collect::<Vec<&str>>();
    let mut out: Vec<&str> = vec![];
    let mut old_line = 0;
    for hunk in diff.hunks {
        while hunk.old_range.start != 0 && old_line < hunk.old_range.start - 1 {
            out.push(old_lines[old_line as usize]);
            old_line += 1;
        }
        for line in hunk.lines {
            match line {
                Line::Context(line) => {
                    let old = old_lines.get(old_line as usize);
                    if old != Some(&line) {
                        return Err(old_line);
                    }
                    if (old_line as usize) < old_lines.len() {
                        out.push(line);
                    }
                    old_line += 1;
                }
                Line::Add(s) => out.push(s),
                Line::Remove(line) => {
                    if old_lines[old_line as usize] != line {
                        return Err(old_line);
                    }
                    old_line += 1;
                }
            }
        }
    }
    for line in old_lines.get((old_line as usize)..).unwrap_or(&[]) {
        out.push(line);
    }
    if old.ends_with('\n') {
        out.push("");
    }
    Ok(out.join("\n"))
}

fn read_to_string(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(data) => Ok(data),
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                Err(anyhow!("Unable to find patch file with path: {:?}", path))
            }
            _ => Err(err.into()),
        },
    }
}

/// Download patched crate sources and apply patch files.
///
/// Reads patch configuration from `[package.metadata.patch.*]` or
/// `[workspace.metadata.patch.*]` in Cargo.toml, downloads each crate
/// to `target/patch/<name>-<version>/`, and applies the listed patches.
pub fn patch() -> Result<()> {
    clear_patch_folder()?;
    let gctx = setup_gctx()?;
    let _lock = gctx.acquire_package_cache_lock(DownloadExclusive)?;
    let workspace_path = find_cargo_toml(&PathBuf::from("."))?;
    let workspace = fetch_workspace(&gctx, &workspace_path)?;
    let (pkg_set, resolve) = resolve_ws(&workspace)?;

    let custom_metadata = workspace.custom_metadata().into_iter().chain(
        workspace
            .members()
            .flat_map(|member| member.manifest().custom_metadata()),
    );

    let patches = custom_metadata.flat_map(get_patches);
    let ids = patches.flat_map(|patch| {
        get_id(patch.name, &patch.version, &resolve).map(|id| (patch, id))
    });

    let mut patched = false;

    for (patch, id) in ids {
        let package = pkg_set.get_one(id)?;
        let path = copy_package(package)?;
        cleanup_package_dir(&path, package)?;
        patched = true;
        apply_patches(patch.name, patch.patches.into_iter(), &path)?;
    }

    if !patched {
        println!("No patches found");
    }
    Ok(())
}

/// Set up a git-based editing environment for developing patches.
///
/// Creates a git repo in `target/patch/<name>-<version>/` with two branches,
/// then drops the user into a subshell in that directory. The branches are:
/// - `upstream`: linear history of upstream releases (one commit per version)
/// - `patched`: forked from the base version, with one commit per existing patch
///
/// If `target` is specified, downloads all intermediate crate versions between
/// the current version and the target, committing each to the `upstream` branch.
/// You can then `git rebase --onto v<target> v<base> patched` to port patches
/// forward.
pub fn edit(crate_name: &str, target: Option<&str>) -> Result<()> {
    let config = read_patch_config_for(crate_name)?;
    let base_version = config.version.clone();
    let patch_dir = find_patch_dir(crate_name, &base_version);

    // Remove existing patch dir if present
    if patch_dir.exists() {
        fs::remove_dir_all(&patch_dir)?;
    }

    // Download and extract the base version
    println!("Downloading {crate_name} {base_version}...");
    let archive = download_crate_archive(crate_name, &base_version)?;
    extract_crate_to(&archive, &patch_dir)?;
    let path = fs::canonicalize(&patch_dir)?;

    // Initialize git repo with a default identity for commits
    git(&path, &["init"])?;
    git(&path, &["config", "user.name", "cargo-patch"])?;
    git(&path, &["config", "user.email", "cargo-patch@localhost"])?;
    git(&path, &["add", "-A"])?;
    git(
        &path,
        &[
            "commit",
            "--no-verify",
            "--allow-empty",
            "-m",
            &format!("{crate_name} {base_version}"),
        ],
    )?;
    git(&path, &["tag", &format!("v{base_version}")])?;

    // If --target specified, populate upstream branch with intermediate versions
    let target_version = if let Some(target_str) = target {
        let target_ver =
            semver::Version::parse(target_str).context("Invalid target version")?;

        println!("Querying versions between {base_version} and {target_ver}...");
        let versions = query_crate_versions(crate_name, &base_version, &target_ver)?;

        for ver in &versions {
            println!("Downloading {crate_name} {ver}...");
            let archive = download_crate_archive(crate_name, ver)?;
            extract_crate_to(&archive, &path)?;
            git(&path, &["add", "-A"])?;
            git(
                &path,
                &[
                    "commit",
                    "--no-verify",
                    "--allow-empty",
                    "-m",
                    &format!("{crate_name} {ver}"),
                ],
            )?;
            git(&path, &["tag", &format!("v{ver}")])?;
        }

        Some(target_ver)
    } else {
        None
    };

    // Create upstream branch at current HEAD
    git(&path, &["checkout", "-b", "upstream"])?;

    // Create patched branch from base version
    git(
        &path,
        &["checkout", "-b", "patched", &format!("v{base_version}")],
    )?;

    // Apply existing patches as individual commits
    for patch_path in &config.patch_paths {
        let raw_name = patch_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "patch".to_string());
        let patch_name = strip_patch_number_prefix(&raw_name).to_string();

        let patch_item = PatchItem {
            path: patch_path,
            source: PatchSource::Default,
        };

        match apply_patches(crate_name, std::iter::once(patch_item), &path) {
            Ok(()) => {
                git(&path, &["add", "-A"])?;
                git(
                    &path,
                    &["commit", "--no-verify", "--allow-empty", "-m", &patch_name],
                )?;
            }
            Err(e) => {
                eprintln!("Warning: failed to apply patch '{patch_name}': {e}");
                // Reset any partial changes
                git(&path, &["checkout", "."])?;
                git(&path, &["clean", "-fd"])?;
            }
        }
    }

    println!();
    println!("Edit environment ready. Dropping into a subshell.");
    println!("  Branch 'patched' is checked out with existing patches applied.");
    println!("  Branch 'upstream' points to the latest upstream version.");

    if let Some(target_ver) = &target_version {
        println!();
        println!("To rebase patches onto v{target_ver}:");
        println!("  git rebase --onto v{target_ver} v{base_version} patched",);
    }

    println!();
    println!("Exit the shell to save patches. Use `exit 1` to discard.");
    println!();

    let should_save = spawn_subshell(&path)?;

    if should_save {
        println!();
        println!("Saving patches...");
        save(crate_name)?;
    } else if std::env::var_os("CARGO_PATCH_NO_SHELL").is_none() {
        println!();
        println!("Shell exited with non-zero status. Patches not saved.");
        println!("You can still save manually with: cargo patch save {crate_name}");
    }

    Ok(())
}

/// Show the diff between the upstream base and the current patched state.
///
/// Finds the merge-base between HEAD and the `upstream` branch, then runs
/// `git diff` to show all changes (including uncommitted work).
/// If no crate name is given, diffs all configured patched crates.
pub fn diff(crate_name: Option<&str>) -> Result<()> {
    let configs = if let Some(name) = crate_name {
        vec![read_patch_config_for(name)?]
    } else {
        read_patch_configs()?
    };

    for config in &configs {
        let patch_dir = find_patch_dir(&config.name, &config.version);
        if !patch_dir.join(".git").exists() {
            eprintln!(
                "No edit environment found at {}. Run 'cargo patch edit {}' first.",
                patch_dir.display(),
                config.name
            );
            continue;
        }

        let base = git(&patch_dir, &["merge-base", "HEAD", "upstream"])?;
        let base = base.trim();
        git_stdout(&patch_dir, &["diff", base])?;
    }

    Ok(())
}

/// Extract patch commits as `.patch` files and update Cargo.toml.
///
/// Commits any uncommitted changes, then iterates over all commits on `patched`
/// since the upstream base. Each commit is exported as a unified diff (with
/// `--no-prefix`) and written to the patch directory. The `patches` list in
/// Cargo.toml metadata is updated to reference the new files.
pub fn save(crate_name: &str) -> Result<()> {
    let config = read_patch_config_for(crate_name)?;
    let version = &config.version;

    let patch_dir = find_patch_dir(crate_name, version);
    if !patch_dir.join(".git").exists() {
        anyhow::bail!(
            "No edit environment found at {}. Run 'cargo patch edit {crate_name}' first.",
            patch_dir.display()
        );
    }

    // Commit any uncommitted changes
    let status = git(&patch_dir, &["status", "--porcelain"])?;
    if !status.trim().is_empty() {
        git(&patch_dir, &["add", "-A"])?;
        git(&patch_dir, &["commit", "--no-verify", "-m", "wip"])?;
    }

    // Find the upstream base (merge-base of HEAD and upstream branch)
    let base = git(&patch_dir, &["merge-base", "HEAD", "upstream"])?;
    let base = base.trim();

    // List commits from base to HEAD
    let log_output = git(
        &patch_dir,
        &[
            "log",
            "--reverse",
            "--format=%H %s",
            &format!("{base}..HEAD"),
        ],
    )?;

    let commits: Vec<(&str, &str)> = log_output
        .lines()
        .filter_map(|line| line.split_once(' '))
        .collect();

    if commits.is_empty() {
        println!("No patch commits found.");
        return Ok(());
    }

    // Determine output directory from existing patch paths, or use a default
    let output_dir = config
        .patch_paths
        .first()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(format!("patches/{crate_name}-{version}")));

    fs::create_dir_all(&output_dir)?;

    // Clean old patch files in the directory
    if output_dir.exists() {
        for entry_file in fs::read_dir(&output_dir)? {
            let entry_file = entry_file?;
            if entry_file.path().extension().is_some_and(|e| e == "patch") {
                fs::remove_file(entry_file.path())?;
            }
        }
    }

    let mut patch_filenames = Vec::new();
    for (i, (hash, subject)) in commits.iter().enumerate() {
        // Sanitize the commit message for use as a filename
        let safe_name: String = subject
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let filename = format!("{:04}-{safe_name}.patch", i + 1);
        let patch_path = output_dir.join(&filename);

        // Generate unified diff for this commit
        let diff_output = git(
            &patch_dir,
            &["diff", "--no-prefix", &format!("{hash}~1"), hash],
        )?;
        fs::write(&patch_path, &diff_output)?;

        println!("Saved: {}", patch_path.display());
        patch_filenames
            .push(output_dir.join(&filename).to_string_lossy().to_string());
    }

    // Update Cargo.toml metadata
    update_cargo_toml_patches(crate_name, &patch_filenames)?;

    println!();
    println!(
        "Saved {} patch(es) to {}",
        patch_filenames.len(),
        output_dir.display()
    );
    println!("Updated patches list in Cargo.toml.");
    Ok(())
}

fn update_cargo_toml_patches(
    crate_name: &str,
    patch_files: &[String],
) -> Result<()> {
    let cargo_toml_path = find_cargo_toml(&PathBuf::from("."))?;
    let content = fs::read_to_string(&cargo_toml_path)?;

    // Build the new patches array as a TOML fragment
    let mut new_array = String::from("[\n");
    for f in patch_files {
        new_array.push_str(&format!("    \"{f}\",\n"));
    }
    new_array.push(']');

    // Try to find and replace the patches array in the metadata section for this crate.
    // We look for a line with `patches = [` inside the right section and replace
    // everything from `[` to the matching `]`.
    let section_markers = [
        format!("[workspace.metadata.patch.{crate_name}]"),
        format!("[package.metadata.patch.{crate_name}]"),
    ];

    let mut updated = false;
    let mut result = String::new();
    let mut in_target_section = false;
    let mut in_patches_array = false;
    let mut bracket_depth = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // Detect section headers
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            in_target_section = section_markers.iter().any(|m| trimmed == m);
        }

        if in_target_section && !in_patches_array && trimmed.starts_with("patches") {
            // Found the patches key - replace with new value
            result.push_str(&format!("patches = {new_array}\n"));
            updated = true;
            // Skip until we find the closing bracket of the old array
            if trimmed.contains('[') {
                bracket_depth = trimmed.matches('[').count() as i32
                    - trimmed.matches(']').count() as i32;
                if bracket_depth > 0 {
                    in_patches_array = true;
                }
            }
            continue;
        }

        if in_patches_array {
            bracket_depth += trimmed.matches('[').count() as i32;
            bracket_depth -= trimmed.matches(']').count() as i32;
            if bracket_depth <= 0 {
                in_patches_array = false;
            }
            continue;
        }

        result.push_str(line);
        result.push('\n');
    }

    if !updated {
        anyhow::bail!(
            "Could not find patches array in [*.metadata.patch.{crate_name}] section of Cargo.toml"
        );
    }

    fs::write(&cargo_toml_path, result)?;
    Ok(())
}

// ========================
// Tests
// ========================

#[cfg(test)]
mod tests {
    use super::apply_patch;
    use patch::Patch;

    #[test]
    fn apply_patch_simply() {
        let patch = r#"--- test	2020-05-21 08:50:06.629765310 +0200
+++ test	2020-05-21 08:50:19.689878523 +0200
@@ -1,6 +1,6 @@
 This is the first line
 
-This is the second line
+This is the patched line
 
 This is the third line
"#;
        let content = r#"This is the first line

This is the second line

This is the third line
"#;
        let patched = r#"This is the first line

This is the patched line

This is the third line
"#;
        let patch = Patch::from_single(patch).expect("Unable to parse patch");
        let test_patched =
            apply_patch(patch, content).expect("Failed to apply patch");
        assert_eq!(patched, test_patched, "Patched content does not match");
    }

    #[test]
    fn apply_patch_middle() {
        let patch = r#"--- test1	2020-05-22 17:30:38.119170176 +0200
+++ test2	2020-05-22 17:30:48.905935473 +0200
@@ -2,8 +2,7 @@
 adipiscing elit, sed do eiusmod tempor 
 incididunt ut labore et dolore magna 
 aliqua. Ut enim ad minim veniam, quis 
-nostrud exercitation ullamco laboris 
-nisi ut aliquip ex ea commodo consequat. 
+PATCHED
 Duis aute irure dolor in reprehenderit 
 in voluptate velit esse cillum dolore 
 eu fugiat nulla pariatur. Excepteur sint 
"#;
        let content = r#"Lorem ipsum dolor sit amet, consectetur 
adipiscing elit, sed do eiusmod tempor 
incididunt ut labore et dolore magna 
aliqua. Ut enim ad minim veniam, quis 
nostrud exercitation ullamco laboris 
nisi ut aliquip ex ea commodo consequat. 
Duis aute irure dolor in reprehenderit 
in voluptate velit esse cillum dolore 
eu fugiat nulla pariatur. Excepteur sint 
occaecat cupidatat non proident, sunt in 
culpa qui officia deserunt mollit anim 
id est laborum.
"#;
        let patched = r#"Lorem ipsum dolor sit amet, consectetur 
adipiscing elit, sed do eiusmod tempor 
incididunt ut labore et dolore magna 
aliqua. Ut enim ad minim veniam, quis 
PATCHED
Duis aute irure dolor in reprehenderit 
in voluptate velit esse cillum dolore 
eu fugiat nulla pariatur. Excepteur sint 
occaecat cupidatat non proident, sunt in 
culpa qui officia deserunt mollit anim 
id est laborum.
"#;
        let patch = Patch::from_single(patch).expect("Unable to parse patch");
        let test_patched =
            apply_patch(patch, content).expect("Failed to apply patch");
        assert_eq!(patched, test_patched, "Patched content does not match");
    }

    #[test]
    fn apply_patch_no_context_override() {
        let patch = r#"--- test        2020-06-06 10:06:44.375560000 +0200
+++ test2       2020-06-06 10:06:49.245635957 +0200
@@ -1,3 +1,3 @@
 test5
-test2
+test4
 test3
"#;
        let content = r#"test1
test2
test3
"#;
        let patch = Patch::from_single(patch).expect("Unable to parse patch");
        assert_eq!(apply_patch(patch, content), Err(0)); // first line context doesn't match
    }
}
