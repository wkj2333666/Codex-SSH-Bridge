use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

const EXPECTED_TOOLS: [&str; 12] = [
    "remote_hosts",
    "remote_list",
    "remote_stat",
    "remote_search",
    "remote_read",
    "remote_output_read",
    "remote_edit_status",
    "remote_sync_edits",
    "remote_discard_edits",
    "remote_apply_patch",
    "remote_write",
    "remote_run",
];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_text(relative_path: impl AsRef<Path>) -> String {
    let path = repository_root().join(relative_path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn read_json(relative_path: impl AsRef<Path>) -> Value {
    let relative_path = relative_path.as_ref();
    let text = read_text(relative_path);
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", relative_path.display()))
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) {
    if path.is_file() {
        files.push(path.to_owned());
        return;
    }

    let mut entries: Vec<_> = fs::read_dir(path)
        .unwrap_or_else(|error| panic!("failed to list {}: {error}", path.display()))
        .map(|entry| entry.expect("failed to read directory entry").path())
        .collect();
    entries.sort();

    for entry in entries {
        collect_files(&entry, files);
    }
}

fn identifier_tokens(text: &str) -> BTreeSet<&str> {
    text.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .collect()
}

fn section<'a>(document: &'a str, heading: &str) -> &'a str {
    let start = document
        .find(heading)
        .unwrap_or_else(|| panic!("missing required Skill section {heading:?}"));
    let body = &document[start + heading.len()..];
    let end = body.find("\n## ").unwrap_or(body.len());
    &body[..end]
}

#[test]
fn plugin_manifest_publishes_the_skill_without_machine_mcp_configuration() {
    let plugin = read_json(".codex-plugin/plugin.json");

    assert_eq!(plugin.get("skills"), Some(&json!("./skills/")));
    assert!(plugin.get("mcpServers").is_none());
}

#[test]
fn mcp_manifest_example_uses_a_user_supplied_release_binary() {
    let manifest = read_json(".mcp.json.example");
    let servers = manifest
        .get("mcpServers")
        .and_then(Value::as_object)
        .expect(".mcp.json must contain an mcpServers object");
    assert_eq!(
        servers.len(),
        1,
        "the plugin must install exactly one MCP server"
    );

    let server = servers
        .get("ssh-bridge")
        .expect("the example must contain one MCP server named ssh-bridge");
    assert_eq!(
        server.get("command"),
        Some(&json!("/absolute/path/to/target/release/codex-ssh-bridge"))
    );
    assert_eq!(server.get("args"), Some(&json!(["mcp"])));
}

#[test]
fn source_package_requires_local_build_and_ignores_user_mcp_config() {
    let root = repository_root();
    assert!(!root.join("bin/codex-ssh-bridge").exists());
    assert!(!root.join(".mcp.json").exists());
    assert!(
        read_text(".gitignore")
            .lines()
            .any(|line| line.trim() == ".mcp.json")
    );
}

#[test]
fn example_config_is_v2_limits_only() {
    let example = read_text("config.example.toml");
    assert!(example.contains("version = 2"));
    for forbidden in [
        "[hosts",
        "root =",
        "description =",
        "read_only",
        "global_concurrency",
        "per_host_concurrency",
    ] {
        assert!(
            !example.contains(forbidden),
            "example retains removed field {forbidden}"
        );
    }
}

#[test]
fn release_workflow_builds_and_packages_all_common_targets() {
    let workflow = read_text(".github/workflows/release.yml");
    for main_target in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "armv7-unknown-linux-gnueabihf",
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "riscv64gc-unknown-linux-gnu",
        "powerpc64le-unknown-linux-gnu",
        "s390x-unknown-linux-gnu",
    ] {
        assert!(
            workflow.contains(main_target),
            "release workflow omits {main_target}"
        );
    }
    for helper_target in [
        "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-musl",
        "armv7-unknown-linux-musleabihf",
        "riscv64gc-unknown-linux-gnu",
        "powerpc64le-unknown-linux-gnu",
        "s390x-unknown-linux-gnu",
    ] {
        assert!(
            workflow.contains(helper_target),
            "release workflow omits {helper_target}"
        );
    }
    assert!(workflow.contains("name: helper-${{ matrix.target }}"));
    assert!(workflow.contains("remote-helpers/$helper"));
    assert!(workflow.contains("Check out tagged source for package resources"));
    assert!(workflow.contains("mkdir -p \"$root/bin\" \"$root/remote-helpers\" \"$root/docs\""));
    assert!(workflow.contains(
        "install -m 0755 \"staging/main-$target/codex-ssh-bridge\" \"$root/bin/codex-ssh-bridge\""
    ));
    for resource in [
        ".codex-plugin",
        "skills",
        "README.md",
        "LICENSE",
        "config.example.toml",
        ".mcp.json.example",
    ] {
        assert!(
            workflow.contains(&format!("            {resource}")),
            "release package omits {resource}"
        );
    }
    assert!(workflow.contains("docs/security.md"));
    assert!(workflow.contains("docs/performance.md"));
    assert!(!workflow.contains("            docs\n"));
    assert!(workflow.contains("test -f \"$root/.codex-plugin/plugin.json\""));
    assert!(workflow.contains("--bin codex-ssh-bridge-helper"));
    assert!(workflow.contains("statically linked|musl"));
    assert!(workflow.contains("find release-assets -maxdepth 1 -type f"));
    assert!(
        workflow.contains("(cd dist && sha256sum \"$name.tar.gz\" > \"$name.tar.gz.sha256\")"),
        "downloaded checksum files must name the adjacent archive, not a CI-internal path"
    );
    assert!(!workflow.contains("sha256sum \"dist/$name.tar.gz\""));
}

#[test]
fn ci_and_release_workflows_use_split_caches() {
    const CACHE_ACTION: &str = "actions/cache@caa296126883cff596d87d8935842f9db880ef25";

    let ci = read_text(".github/workflows/ci.yml");
    assert_eq!(ci.matches(CACHE_ACTION).count(), 7);
    assert_eq!(ci.matches("Restore pinned Rust toolchain cache").count(), 2);
    assert_eq!(
        ci.matches("Restore shared Cargo dependency cache").count(),
        2
    );
    assert_eq!(ci.matches("Restore diagnostics target cache").count(), 1);
    assert_eq!(ci.matches("Restore quality target cache").count(), 0);
    assert!(!ci.contains("rust-target-quality"));
    assert_eq!(ci.matches("Restore ripgrep tool cache").count(), 2);
    assert!(ci.contains("~/.rustup/toolchains/${{ env.RUST_TOOLCHAIN }}-*"));
    assert!(ci.contains("~/.cargo/registry"));
    assert!(ci.contains("~/.cargo/git"));
    assert!(ci.contains("target"));
    assert_eq!(ci.matches("Compute dependency cache key").count(), 2);
    assert_eq!(ci.matches("steps.dependency-cache.outputs.key").count(), 3);
    assert!(!ci.contains("hashFiles('Cargo.lock')"));
    assert!(!ci.contains("Restore Rust build cache"));

    let release = read_text(".github/workflows/release.yml");
    assert_eq!(release.matches(CACHE_ACTION).count(), 8);
    assert_eq!(
        release
            .matches("Restore pinned Rust toolchain cache")
            .count(),
        2
    );
    assert_eq!(release.matches("Compute dependency cache key").count(), 2);
    assert_eq!(
        release
            .matches("steps.dependency-cache.outputs.key")
            .count(),
        4
    );
    assert_eq!(
        release
            .matches("Restore shared Cargo dependency cache")
            .count(),
        2
    );
    assert_eq!(release.matches("Restore cross binary cache").count(), 2);
    assert_eq!(release.matches("Verify cross compiler").count(), 2);
    assert!(release.contains("~/.rustup/toolchains/${{ env.RUST_TOOLCHAIN }}-*"));
    assert_eq!(
        release
            .matches("rust-target-cross-${{ env.RUST_TOOLCHAIN }}-${{ matrix.target }}")
            .count(),
        4
    );
    assert!(release.contains("path: target"));
    assert!(release.contains("steps.cross-cache.outputs.cache-hit != 'true'"));
}

#[test]
fn installed_chain_has_no_python_runtime_or_legacy_module_references() {
    let root = repository_root();
    let mut files = Vec::new();
    collect_files(&root.join(".codex-plugin"), &mut files);
    files.push(root.join(".mcp.json.example"));
    collect_files(&root.join("skills"), &mut files);
    files.push(root.join("README.md"));
    files.sort();
    files.dedup();

    let forbidden = ["python3", "server.py", "ssh_bridge"];
    let mut violations = Vec::new();
    for path in files {
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for needle in forbidden {
            if text.contains(needle) {
                let relative = path.strip_prefix(&root).unwrap_or(&path);
                violations.push(format!("{} references {needle:?}", relative.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "installed plugin chain still references the Python/legacy runtime:\n{}",
        violations.join("\n")
    );
}

#[test]
fn skill_names_exactly_the_nine_remote_tools() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md");
    let identifiers = identifier_tokens(&skill);
    let actual_remote_tools: BTreeSet<_> = identifiers
        .iter()
        .copied()
        .filter(|token| token.starts_with("remote_"))
        .collect();
    let expected_remote_tools: BTreeSet<_> = EXPECTED_TOOLS.into_iter().collect();

    assert_eq!(
        actual_remote_tools, expected_remote_tools,
        "the Skill must name exactly the public MCP tool set"
    );
}

#[test]
fn skill_names_no_legacy_ssh_tools() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md");
    let identifiers = identifier_tokens(&skill);
    let legacy_tools: Vec<_> = identifiers
        .iter()
        .copied()
        .filter(|token| token.starts_with("ssh_"))
        .collect();
    assert!(
        legacy_tools.is_empty(),
        "the Skill still names legacy ssh_ tools: {legacy_tools:?}"
    );
}

#[test]
fn skill_exposes_no_sshfs_mcp_tool() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md");
    let identifiers = identifier_tokens(&skill);
    let sshfs_mcp_tools: Vec<_> = identifiers
        .iter()
        .copied()
        .filter(|token| {
            token.starts_with("remote_")
                && (token.contains("sshfs")
                    || token.ends_with("_mount")
                    || token.ends_with("_unmount"))
        })
        .collect();
    assert!(
        sshfs_mcp_tools.is_empty(),
        "SSHFS must remain a CLI workflow, not an MCP tool: {sshfs_mcp_tools:?}"
    );
}

#[test]
fn skill_teaches_the_low_burden_default_workflow_in_order() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md");
    let workflow = section(&skill, "## Default workflow");
    let search = workflow
        .find("remote_search")
        .expect("default workflow must start from bounded remote search");
    let read = workflow
        .find("remote_read")
        .expect("default workflow must read before changing files");
    let patch = workflow
        .find("remote_apply_patch")
        .expect("default workflow must prefer remote_apply_patch");
    let run = workflow
        .find("remote_run")
        .expect("default workflow must verify with remote_run");
    assert!(search < read && read < patch && patch < run);
}

#[test]
fn skill_batches_related_edits_before_remote_barriers() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md").to_ascii_lowercase();
    let workflow = section(&skill, "## default workflow");

    for required in [
        "one logical change",
        "use `remote_read` to inspect",
        "do not use `remote_run` with `cat`, `sed`, `nl`, or `grep`",
        "meaningful behavior boundary",
        "do not batch unrelated changes",
        "red→green",
    ] {
        assert!(
            workflow.contains(required),
            "default workflow omits edit-batching guidance {required:?}"
        );
    }
}

#[test]
fn skill_states_remote_shell_output_and_sshfs_boundaries() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md").to_ascii_lowercase();
    for required in [
        "every path",
        "untrusted",
        "actual shell",
        "posix",
        "bash-only",
        "fallback",
        "human-only",
        "not an agent workspace",
    ] {
        assert!(
            skill.contains(required),
            "Skill omits required boundary phrase {required:?}"
        );
    }
}

#[test]
fn skill_closes_search_stdin_and_patch_schema_ambiguities() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md").to_ascii_lowercase();
    for required in [
        "case-sensitive literal",
        "stdin is an object",
        "encoding",
        "value",
        "absolute remote path",
    ] {
        assert!(
            skill.contains(required),
            "Skill omits schema clarification {required:?}"
        );
    }
}

#[test]
fn skill_states_buffered_edit_durability_without_burdening_the_agent() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md")
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "bounded in-memory edit cache",
        "within 30 seconds",
        "16 kib",
        "clean mcp shutdown",
        "buffered write may fail",
        "do not manage generations",
        "remote_edit_status",
        "remote_sync_edits",
        "remote_discard_edits",
        "normal editing",
    ] {
        assert!(
            skill.contains(required),
            "Skill omits buffered-edit boundary phrase {required:?}"
        );
    }
}

#[test]
fn skill_and_reference_teach_the_durable_remote_job_boundary() {
    let skill = read_text("skills/remote-ssh-ops/SKILL.md").to_ascii_lowercase();
    let operations =
        read_text("skills/remote-ssh-ops/references/operations.md").to_ascii_lowercase();
    for document in [&skill, &operations] {
        for tool in [
            "remote_job_start",
            "remote_job_status",
            "remote_job_logs",
            "remote_job_cancel",
            "remote_job_list",
            "remote_job_delete",
        ] {
            assert!(document.contains(tool), "Job reference omits {tool}");
        }
        for boundary in [
            "remote_run remains synchronous",
            "codex task",
            "bridge disconnect",
            "survives",
            "never submit the command again blindly",
            "no automatic restart after a remote reboot",
        ] {
            assert!(
                document.contains(boundary),
                "Job reference omits lifecycle boundary {boundary:?}"
            );
        }
    }
}

#[test]
fn public_docs_state_remote_job_storage_security_and_retention() {
    let docs = [
        read_text("README.md"),
        read_text("docs/security.md"),
        read_text("docs/performance.md"),
    ]
    .join("\n")
    .to_ascii_lowercase();
    for required in [
        ".local/state/codex-ssh-bridge/jobs",
        "0700",
        "0600",
        "no-follow",
        "process start",
        "64 mib",
        "seven-day",
        "lazy retention",
        "persistent binary helper",
        "no automatic restart after a remote reboot",
    ] {
        assert!(
            docs.contains(required),
            "public Job documentation omits {required:?}"
        );
    }
}

#[test]
fn local_installation_has_a_transactional_rust_entrypoint_for_mcp_and_skill() {
    let cli = read_text("src/cli.rs");
    assert!(cli.contains("mod install;"));
    assert!(cli.contains("Install(InstallArgs)"));
    assert!(cli.contains("Uninstall(InstallArgs)"));
    assert!(read_text("src/cli/install.rs").contains("pub async fn install_user"));

    let readme = read_text("README.md");
    assert!(readme.contains("codex-ssh-bridge install --user"));
    assert!(readme.contains(".codex/skills/remote-ssh-ops"));
    assert!(readme.contains(".local/bin/codex-ssh-bridge"));
}

#[test]
fn release_package_excludes_private_superpowers_documents() {
    let workflow = read_text(".github/workflows/release.yml");
    assert!(workflow.contains("docs/security.md"));
    assert!(workflow.contains("docs/performance.md"));
    assert!(!workflow.contains("            docs\n"));
    assert!(!workflow.contains("docs/superpowers"));
}
