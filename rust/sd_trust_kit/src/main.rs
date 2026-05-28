use sd_trust_kit::{
    verify_pdf, verify_pdf_including_revocation_with_options, verify_pdf_with_options, CrlCache,
    EuTrustedListCache, RevocationOptions, ValidationReport, VerificationOptions,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

enum Command {
    Help,
    Verify(Cli),
}

struct Cli {
    pdf_path: PathBuf,
    pretty: bool,
    mode: Mode,
}

enum Mode {
    Core,
    OfflineFixtures(PathBuf),
    FullFixtures(PathBuf),
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    match parse_args(std::env::args().skip(1))? {
        Command::Help => {
            print_usage();
            Ok(())
        }
        Command::Verify(cli) => {
            let report = verify_from_cli(&cli)?;
            write_report(&report, cli.pretty)
        }
    }
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut pdf_path = None;
    let mut pretty = false;
    let mut mode = Mode::Core;
    let mut mode_set = false;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "--pretty" => pretty = true,
            "--offline-fixtures" => {
                let path = option_path(&mut args, "--offline-fixtures")?;
                set_mode(&mut mode, &mut mode_set, Mode::OfflineFixtures(path))?;
            }
            "--full-fixtures" => {
                let path = option_path(&mut args, "--full-fixtures")?;
                set_mode(&mut mode, &mut mode_set, Mode::FullFixtures(path))?;
            }
            _ if arg.starts_with('-') => {
                return Err(format!("Unknown option: {arg}\n\n{}", usage()));
            }
            _ => {
                if pdf_path.replace(PathBuf::from(&arg)).is_some() {
                    return Err(format!("Unexpected extra PDF path: {arg}\n\n{}", usage()));
                }
            }
        }
    }

    let Some(pdf_path) = pdf_path else {
        return Err(format!("Missing PDF path.\n\n{}", usage()));
    };

    Ok(Command::Verify(Cli {
        pdf_path,
        pretty,
        mode,
    }))
}

fn option_path(
    args: &mut impl Iterator<Item = String>,
    option_name: &str,
) -> Result<PathBuf, String> {
    args.next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{option_name} requires a directory path.\n\n{}", usage()))
}

fn set_mode(current: &mut Mode, mode_set: &mut bool, next: Mode) -> Result<(), String> {
    if *mode_set {
        return Err(format!(
            "Choose only one fixture mode: --offline-fixtures or --full-fixtures.\n\n{}",
            usage()
        ));
    }
    *current = next;
    *mode_set = true;
    Ok(())
}

fn verify_from_cli(cli: &Cli) -> Result<ValidationReport, String> {
    let pdf = fs::read(&cli.pdf_path)
        .map_err(|error| format!("Couldn't read {}: {error}", cli.pdf_path.display()))?;

    match &cli.mode {
        Mode::Core => Ok(verify_pdf(&pdf)),
        Mode::OfflineFixtures(fixtures_dir) => {
            let options = offline_fixture_verification_options(fixtures_dir)?;
            Ok(verify_pdf_with_options(&pdf, &options))
        }
        Mode::FullFixtures(fixtures_dir) => {
            let eu_cache = trusted_list_cache(fixtures_dir)?;
            let options = full_fixture_verification_options(fixtures_dir, &eu_cache)?;
            let revocation_options = RevocationOptions {
                crl_cache: CrlCache::from_directory(fixtures_dir.join("crl_cache")).map_err(
                    |error| {
                        format!(
                            "Couldn't read CRL cache fixtures from {}: {error}",
                            fixtures_dir.join("crl_cache").display()
                        )
                    },
                )?,
                now_unix_seconds: eu_cache.fetched_at_unix_time(),
            };
            Ok(verify_pdf_including_revocation_with_options(
                &pdf,
                &options,
                &revocation_options,
            ))
        }
    }
}

fn offline_fixture_verification_options(
    fixtures_dir: &Path,
) -> Result<VerificationOptions, String> {
    Ok(VerificationOptions {
        signer_trust_anchors: fixture_certs(fixtures_dir, "system_trust_anchors")?,
        ..VerificationOptions::default()
    })
}

fn full_fixture_verification_options(
    fixtures_dir: &Path,
    eu_cache: &EuTrustedListCache,
) -> Result<VerificationOptions, String> {
    let mut signer_trust_anchors =
        fixture_certs_matching(fixtures_dir, "app_trust_anchors", "ro-cei")?;
    signer_trust_anchors.extend(fixture_certs(fixtures_dir, "system_trust_anchors")?);

    Ok(VerificationOptions {
        signer_trust_anchors: unique_bytes(signer_trust_anchors),
        signer_trust_anchor_sets: eu_cache.signer_trust_anchor_sets(),
        timestamp_trust_anchors: fixture_certs_matching(
            fixtures_dir,
            "app_trust_anchors",
            "sts-root-g2",
        )?,
        timestamp_trust_anchor_sets: eu_cache.timestamp_trust_anchor_sets(),
        timestamp_certificate_sha256_pins: fixture_texts(fixtures_dir, "app_trust_pins")?,
    })
}

fn trusted_list_cache(fixtures_dir: &Path) -> Result<EuTrustedListCache, String> {
    let path = fixtures_dir
        .join("eu_trusted_list")
        .join("trusted-certificates-v2.json");
    let data =
        fs::read(&path).map_err(|error| format!("Couldn't read {}: {error}", path.display()))?;
    EuTrustedListCache::from_json_slice(&data)
        .map_err(|error| format!("Couldn't decode {}: {error}", path.display()))
}

fn fixture_certs(fixtures_dir: &Path, name: &str) -> Result<Vec<Vec<u8>>, String> {
    fixture_certs_matching(fixtures_dir, name, "")
}

fn fixture_certs_matching(
    fixtures_dir: &Path,
    name: &str,
    filename_contains: &str,
) -> Result<Vec<Vec<u8>>, String> {
    let paths = fixture_paths_with_extension(fixtures_dir, name, "der", filename_contains)?;
    paths
        .iter()
        .map(|path| {
            fs::read(path).map_err(|error| format!("Couldn't read {}: {error}", path.display()))
        })
        .collect()
}

fn fixture_texts(fixtures_dir: &Path, name: &str) -> Result<Vec<String>, String> {
    let paths = fixture_paths_with_extension(fixtures_dir, name, "txt", "")?;
    paths
        .iter()
        .map(|path| {
            fs::read_to_string(path)
                .map(|text| text.trim().to_owned())
                .map_err(|error| format!("Couldn't read {}: {error}", path.display()))
        })
        .collect()
}

fn fixture_paths_with_extension(
    fixtures_dir: &Path,
    name: &str,
    extension: &str,
    filename_contains: &str,
) -> Result<Vec<PathBuf>, String> {
    let dir = fixtures_dir.join(name);
    let entries = fs::read_dir(&dir)
        .map_err(|error| format!("Couldn't read fixture directory {}: {error}", dir.display()))?;
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().and_then(|ext| ext.to_str()) == Some(extension)
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(filename_contains))
        })
        .collect();
    paths.sort();
    Ok(paths)
}

fn unique_bytes(items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn write_report(report: &ValidationReport, pretty: bool) -> Result<(), String> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if pretty {
        serde_json::to_writer_pretty(&mut handle, report)
    } else {
        serde_json::to_writer(&mut handle, report)
    }
    .map_err(|error| format!("Couldn't serialize validation report: {error}"))?;
    writeln!(handle).map_err(|error| format!("Couldn't write validation report: {error}"))
}

fn print_usage() {
    println!("{}", usage());
}

fn usage() -> &'static str {
    "Usage: sd-trust-validate [OPTIONS] <PDF>

Options:
  --pretty                  Pretty-print the JSON validation report
  --offline-fixtures <DIR>  Use system trust anchor fixtures without revocation
  --full-fixtures <DIR>     Use app/system/EU/CRL fixtures and include revocation
  -h, --help                Show this help"
}
