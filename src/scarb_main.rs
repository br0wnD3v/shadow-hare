/// scarb-shadowhare / scarb-shdr — invoked as:
///   `scarb shadowhare <subcommand>`
///   `scarb shdr <subcommand>`
///
/// Scarb sets these environment variables automatically:
///   SCARB_MANIFEST_PATH — path to the project's Scarb.toml
///   SCARB_TARGET_DIR    — path to the build output directory
///   SCARB_PROFILE       — active build profile
///
/// We delegate to the same logic as shadowhare but auto-discover
/// Sierra artifacts from SCARB_TARGET_DIR.

fn main() {
    // Scarb passes the subcommand name as argv[1] when invoking scarb-<name>.
    // Strip it so clap sees the right arguments.
    let mut args: Vec<String> = std::env::args().collect();
    if args
        .get(1)
        .map(|s| s == "shadowhare" || s == "shdr" || s == "analyzer")
        .unwrap_or(false)
    {
        args.remove(1);
    }

    // Inject --manifest if SCARB_MANIFEST_PATH is set
    if let Ok(manifest) = std::env::var("SCARB_MANIFEST_PATH") {
        if !args.contains(&"--manifest".to_string()) {
            args.push("--manifest".to_string());
            args.push(manifest);
        }
    }

    if let Ok(target_dir) = std::env::var("SCARB_TARGET_DIR") {
        let profile = std::env::var("SCARB_PROFILE").unwrap_or_else(|_| "dev".to_string());
        let artifacts_dir = format!("{target_dir}/{profile}");

        // Inject target dir after "detect" or "update-baseline" subcommand
        let detect_idx = args
            .iter()
            .position(|a| a == "detect" || a == "update-baseline");
        if let Some(idx) = detect_idx {
            // Check if a path argument is already present after the subcommand
            let has_path_arg = args
                .get(idx + 1)
                .map(|a| !a.starts_with('-'))
                .unwrap_or(false);
            if !has_path_arg {
                args.insert(idx + 1, artifacts_dir);
            }
        }
    }

    // Re-exec as the main CLI binary (shadowhare/shdr), not this scarb wrapper,
    // otherwise we'd recurse forever.
    let mut program = std::path::PathBuf::from(&args[0]);
    if let Some(name) = program.file_name().and_then(|n| n.to_str()) {
        let target = if name.contains("scarb-shdr") {
            "shdr"
        } else {
            "shadowhare"
        };
        program.set_file_name(target);
    } else {
        program = std::path::PathBuf::from("shadowhare");
    }

    let status = std::process::Command::new(&program)
        .args(&args[1..])
        .status()
        .or_else(|_| {
            std::process::Command::new("shadowhare")
                .args(&args[1..])
                .status()
        })
        .unwrap_or_else(|e| {
            eprintln!("Failed to exec shadowhare: {e}");
            std::process::exit(2);
        });

    std::process::exit(status.code().unwrap_or(2));
}
