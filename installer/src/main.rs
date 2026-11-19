//! Unpacks Rusty and the router, makes a client key for this PC if there isn't one, and
//! installs the service. Usage: rusty-setup.exe [--dir C:\Rusty]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

macro_rules! files {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_bytes!(concat!(env!("PACKAGE_DIR"), "/", $name)) as &[u8])),*]
    };
}

const FILES: &[(&str, &[u8])] = files!(
    "session-router.exe",
    "wintun.dll",
    "rusty-service.exe",
    "rusty-ctl.exe",
    "session-router.ini",
    "rusty-service.json",
    "bootstrap.signed",
    "README.txt",
    "LICENSE",
    "wintun-LICENSE.txt",
);

const ZB32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

fn zbase32(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ZB32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ZB32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Session Router key file: hex of seed followed by public key, then a newline.
fn ensure_key(dir: &Path) -> io::Result<String> {
    let path = dir.join("client.key");
    let pub_key = if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        let t = text.trim();
        if t.len() != 128 {
            return Err(io::Error::other("client.key isn't a 128-hex key file"));
        }
        (0..32)
            .map(|i| u8::from_str_radix(&t[64 + 2 * i..66 + 2 * i], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(io::Error::other)?
    } else {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| io::Error::other(e.to_string()))?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        f.write_all(format!("{}{}\n", hex(&seed), hex(&pk)).as_bytes())?;
        drop(f);
        // Only admins and SYSTEM may read the key.
        let _ = Command::new("icacls")
            .arg(&path)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-32-544:F",
                "*S-1-5-18:F",
            ])
            .output();
        pk.to_vec()
    };
    Ok(format!("{}.sesh", zbase32(&pub_key)))
}

fn sc(args: &[&str]) -> Option<String> {
    let o = Command::new("sc.exe").args(args).output().ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Where the installed service's program lives and whether it is running, if installed.
fn installed_service() -> Option<(PathBuf, bool)> {
    let qc = sc(&["qc", "RustySessionRouter"])?;
    let line = qc.lines().find(|l| l.contains("BINARY_PATH_NAME"))?;
    let raw = line.split_once(':')?.1.trim();
    let exe = if let Some(rest) = raw.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        raw.split_whitespace().next()?.to_string()
    };
    let running = sc(&["query", "RustySessionRouter"])
        .map(|q| q.contains("RUNNING") || q.contains("PENDING"))
        .unwrap_or(false);
    Some((PathBuf::from(exe), running))
}

/// Stop the service and wait until Windows says it has stopped, so its files can be replaced.
fn stop_service() -> Result<(), String> {
    let _ = sc(&["stop", "RustySessionRouter"]);
    for _ in 0..60 {
        let q = sc(&["query", "RustySessionRouter"]).unwrap_or_default();
        if q.contains("STOPPED") {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    Err(
        "RustySessionRouter didn't stop within 30 s. Run \"sc.exe stop RustySessionRouter\", \
         wait a few seconds, and start this setup again."
            .into(),
    )
}

fn same_dir(exe: &Path, dir: &Path) -> bool {
    let a = exe.parent().and_then(|p| p.canonicalize().ok());
    let b = dir.canonicalize().ok();
    a.is_some() && a == b
}

fn print_address(dir: &Path, sesh: &str) {
    println!();
    println!("This PC's client address (an exit with an allow list needs it; never share client.key):");
    println!();
    println!("    {sesh}");
    println!();
    println!(
        "Saved in {}. Next steps are in {}.",
        dir.join("my-client-address.txt").display(),
        dir.join("README.txt").display()
    );
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    println!("Rusty setup {}", env!("RUSTY_VERSION"));
    let dir = match args.iter().position(|a| a == "--dir") {
        Some(i) => PathBuf::from(args.get(i + 1).ok_or("--dir needs a folder")?),
        None => PathBuf::from(r"C:\Rusty"),
    };
    std::fs::create_dir_all(&dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    let mut already = false;
    let mut was_running = false;
    if let Some((exe, running)) = installed_service() {
        if !same_dir(&exe, &dir) {
            return Err(format!(
                "RustySessionRouter is already installed from {}. Remove it first with \
                 \"rusty-service.exe uninstall\" in that folder.",
                exe.display()
            ));
        }
        if running {
            println!(
                "RustySessionRouter is running; stopping it to update (this unmaps the exit)."
            );
            stop_service()?;
        }
        println!("RustySessionRouter is already installed here; updating its files.");
        was_running = running;
        already = true;
    }
    for (name, data) in FILES {
        std::fs::write(dir.join(name), data).map_err(|e| {
            format!(
                "can't write {name}: {e}. Close anything using {} and start this setup again.",
                dir.display()
            )
        })?;
    }
    println!("Unpacked {} files to {}", FILES.len(), dir.display());

    let sesh = ensure_key(&dir).map_err(|e| format!("client key: {e}"))?;
    std::fs::write(dir.join("my-client-address.txt"), format!("{sesh}\r\n"))
        .map_err(|e| e.to_string())?;

    if already {
        println!("Updated. Kept the existing client.key and service.");
        if was_running {
            println!("The service was stopped for the update; start it with: sc.exe start RustySessionRouter");
        }
        print_address(&dir, &sesh);
        return Ok(());
    }

    let out = Command::new(dir.join("rusty-service.exe"))
        .arg("install")
        .current_dir(&dir)
        .output()
        .map_err(|e| format!("couldn't run rusty-service.exe: {e}"))?;
    print!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        return Err("rusty-service.exe install failed".into());
    }

    print_address(&dir, &sesh);
    Ok(())
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Setup failed: {e}");
            1
        }
    };
    if !std::env::args().any(|a| a == "--quiet") {
        print!("\nPress Enter to close.");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut String::new());
    }
    std::process::exit(code);
}
