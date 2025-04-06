use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use regex::Regex;
use std::process::Command;
use std::str;
use std::path::Path;
use serde::{Serialize, Deserialize};

mod security;
mod wpa_cracker;
mod packet_capture;
mod web_ui;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for available Wi-Fi networks
    Scan {
        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Check security of a specific network
    Security {
        /// SSID of the network to check
        #[arg(short, long)]
        ssid: String,

        /// BSSID (MAC address) of the network to check
        #[arg(short, long)]
        bssid: String,

        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Perform a deauthentication attack (EDUCATIONAL PURPOSES ONLY)
    Deauth {
        /// BSSID (MAC address) of the target access point
        #[arg(short, long)]
        bssid: String,

        /// MAC address of the client to deauthenticate (optional)
        #[arg(short = 'm', long)]
        client: Option<String>,

        /// Number of deauth packets to send
        #[arg(short, long, default_value = "5")]
        count: u32,

        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Capture a WPA handshake (EDUCATIONAL PURPOSES ONLY)
    CaptureHandshake {
        /// BSSID (MAC address) of the target network
        #[arg(short, long)]
        bssid: String,

        /// Channel of the target network
        #[arg(short, long)]
        channel: u8,

        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Crack a WPA password using a dictionary attack (EDUCATIONAL PURPOSES ONLY)
    CrackWPA {
        /// Path to the wordlist file
        #[arg(short, long)]
        wordlist: String,

        /// SSID of the target network
        #[arg(short, long)]
        ssid: String,

        /// BSSID (MAC address) of the target network
        #[arg(short, long)]
        bssid: String,
    },

    /// Run a demo of WPA cracking (EDUCATIONAL PURPOSES ONLY)
    DemoWPACrack {
        /// Password to use in the demo (will be "found" by the cracker)
        #[arg(short, long, default_value = "password123")]
        password: String,
    },

    /// Monitor wireless traffic (EDUCATIONAL PURPOSES ONLY)
    MonitorTraffic {
        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,

        /// Duration in seconds to monitor
        #[arg(short, long, default_value = "30")]
        duration: u64,
    },

    /// Put wireless interface in monitor mode (EDUCATIONAL PURPOSES ONLY)
    MonitorMode {
        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,

        /// Disable monitor mode instead of enabling it
        #[arg(short, long)]
        disable: bool,
    },

    /// Start the web UI
    WebUI {
        /// Port to run the web server on
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },

    /// List all captured handshakes
    ListHandshakes,

    /// Perform real-world testing on a network (EDUCATIONAL PURPOSES ONLY)
    RealWorldTest {
        /// SSID of the network to test
        #[arg(short, long)]
        ssid: String,

        /// BSSID (MAC address) of the network to test
        #[arg(short, long)]
        bssid: String,

        /// Channel of the target network
        #[arg(short, long)]
        channel: u8,

        /// Specify the wireless interface (default: auto-detect)
        #[arg(short, long)]
        interface: Option<String>,
    },

    /// Verify a captured handshake
    VerifyHandshake {
        /// Path to the handshake capture file
        #[arg(short, long)]
        capture_file: String,

        /// SSID of the network (optional)
        #[arg(short, long)]
        ssid: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WifiNetwork {
    ssid: String,
    bssid: String,
    channel: String,
    signal_strength: String,
    security: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Scan { interface }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} Using interface: {}", "[*]".blue(), interface);

            let networks = scan_networks(&interface)?;
            display_networks(&networks);
        },
        Some(Commands::Security { ssid, bssid, interface }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} Checking security for network: {}", "[*]".blue(), ssid);
            println!("{} Using interface: {}", "[*]".blue(), interface);

            let vulnerabilities = security::check_network_security(ssid, bssid)?;

            if vulnerabilities.is_empty() {
                println!("{} No obvious vulnerabilities found", "[+]".green());
            } else {
                println!("{} Found {} potential vulnerabilities:", "[!]".red(), vulnerabilities.len());
                for (i, vuln) in vulnerabilities.iter().enumerate() {
                    println!("{} {}", format!("[{}]", i+1).red(), vuln);
                }
            }
        },
        Some(Commands::Deauth { bssid, client, count, interface }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT PERMISSION", "[!]".red());

            // Default client MAC if not provided
            let client_mac = client.clone().unwrap_or_else(|| "FF:FF:FF:FF:FF:FF".to_string());

            // Perform deauth
            packet_capture::deauth_client(&interface, bssid, &client_mac, *count)?;
        },
        Some(Commands::CaptureHandshake { bssid, channel, interface }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT PERMISSION", "[!]".red());

            // Capture handshake
            let handshake = packet_capture::capture_handshake(&interface, bssid, *channel)?;

            println!("{} Handshake information:", "[+]".green());
            println!("   SSID: {}", handshake.ssid);
            println!("   BSSID: {}", handshake.bssid);
            println!("   Client MAC: {}", handshake.client_mac);
            println!("   Capture file: {}", handshake.capture_file);
            println!("   Timestamp: {}", handshake.timestamp);
            println!("   Verified: {}", if handshake.verified { "Yes".green() } else { "No".red() });

            if handshake.verified {
                println!("{} Handshake was successfully captured and verified", "[+]".green());
                println!("{} You can now attempt to crack it using:", "[*]".blue());
                println!("   wifi_scanner crack-wpa --wordlist <path_to_wordlist> --ssid \"{}\" --bssid {}",
                         handshake.ssid, handshake.bssid);
            } else {
                println!("{} Handshake may not be complete. Try again or deauthenticate clients first", "[!]".yellow());
                println!("{} You can deauthenticate clients using:", "[*]".blue());
                println!("   wifi_scanner deauth --bssid {} --count 5", handshake.bssid);
            }
        },
        Some(Commands::CrackWPA { wordlist, ssid, bssid }) => {
            println!("{} EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT PERMISSION", "[!]".red());

            // Check if wordlist exists
            if !Path::new(wordlist).exists() {
                println!("{} Wordlist file not found: {}", "[!]".red(), wordlist);
                return Ok(());
            }

            // Generate test data for educational purposes
            println!("{} This is a simulation for educational purposes", "[*]".blue());
            println!("{} In a real scenario, you would need a captured handshake", "[*]".blue());

            let (_, password, anonce, snonce, _ap_mac, _client_mac, mic, eapol_data) =
                wpa_cracker::generate_test_handshake();

            // Add the password to the wordlist for demo purposes
            let temp_wordlist = "temp_wordlist.txt";
            wpa_cracker::create_test_wordlist(temp_wordlist, &password)?;

            // Convert MAC addresses from string to bytes
            let ap_mac_bytes = wpa_cracker::hex_to_bytes(&bssid.replace(":", ""))?;
            let client_mac_str = "AA:BB:CC:DD:EE:FF";
            let client_mac_bytes = wpa_cracker::hex_to_bytes(&client_mac_str.replace(":", ""))?;

            // Run dictionary attack
            let result = wpa_cracker::dictionary_attack(
                temp_wordlist,
                ssid,
                &anonce,
                &snonce,
                &ap_mac_bytes,
                &client_mac_bytes,
                &mic,
                &eapol_data
            )?;

            if let Some(found_password) = result {
                println!("{} Password found: {}", "[+]".green(), found_password);
            } else {
                println!("{} Password not found in wordlist", "[!]".red());
            }

            // Clean up temporary wordlist
            std::fs::remove_file(temp_wordlist).ok();
        },
        Some(Commands::DemoWPACrack { password }) => {
            println!("{} EDUCATIONAL PURPOSES ONLY - DEMO MODE", "[!]".yellow());
            println!("{} This is a demonstration of how WPA cracking works", "[*]".blue());
            println!("{} No actual networks are being tested", "[*]".blue());

            // Generate test data
            let (ssid, _, anonce, snonce, ap_mac, client_mac, mic, eapol_data) =
                wpa_cracker::generate_test_handshake();

            println!("{} Generated test network:", "[+]".green());
            println!("   SSID: {}", ssid);
            println!("   BSSID: {}", wpa_cracker::format_mac(&ap_mac));
            println!("   Client: {}", wpa_cracker::format_mac(&client_mac));

            // Create a temporary wordlist with the password
            let temp_wordlist = "demo_wordlist.txt";
            wpa_cracker::create_test_wordlist(temp_wordlist, password)?;

            println!("{} Created demo wordlist with 10 passwords", "[+]".green());
            println!("{} Starting dictionary attack simulation...", "[*]".blue());

            // Run dictionary attack
            let result = wpa_cracker::dictionary_attack(
                temp_wordlist,
                &ssid,
                &anonce,
                &snonce,
                &ap_mac,
                &client_mac,
                &mic,
                &eapol_data
            )?;

            if let Some(found_password) = result {
                println!("{} Password found: {}", "[+]".green(), found_password);
                println!("{} This demonstrates how dictionary attacks work against WPA", "[*]".blue());
                println!("{} Always use strong, unique passwords for your Wi-Fi networks", "[*]".blue());
            }

            // Clean up
            std::fs::remove_file(temp_wordlist).ok();
        },
        Some(Commands::MonitorTraffic { interface, duration }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT PERMISSION", "[!]".red());

            // Analyze traffic
            packet_capture::analyze_traffic(&interface, *duration)?;
        },
        Some(Commands::MonitorMode { interface, disable }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT PERMISSION", "[!]".red());

            if *disable {
                // Disable monitor mode
                packet_capture::disable_monitor_mode(&interface)?;
            } else {
                // Enable monitor mode
                let monitor_interface = packet_capture::enable_monitor_mode(&interface)?;
                println!("{} Monitor mode enabled on interface: {}", "[+]".green(), monitor_interface);
                println!("{} Don't forget to disable monitor mode when finished", "[*]".blue());
                println!("{} Use: wifi_scanner monitor-mode --interface {} --disable", "[*]".blue(), interface);
            }
        },
        Some(Commands::WebUI { port }) => {
            println!("{} Starting web UI on http://localhost:{}", "[*]".blue(), port);
            println!("{} Press Ctrl+C to stop the server", "[*]".blue());

            // Use tokio runtime to run the web server
            actix_rt::System::new().block_on(async {
                web_ui::start_server(*port).await
            })?;
        },
        Some(Commands::ListHandshakes) => {
            println!("{} Listing all captured handshakes", "[*]".blue());

            let handshakes = packet_capture::list_handshakes()?;

            if handshakes.is_empty() {
                println!("{} No handshakes found", "[!]".yellow());
            } else {
                println!("{} Found {} handshakes:", "[+]".green(), handshakes.len());

                for (i, handshake) in handshakes.iter().enumerate() {
                    println!("{} Handshake #{}", "[+]".green(), i + 1);
                    println!("   SSID: {}", handshake.ssid);
                    println!("   BSSID: {}", handshake.bssid);
                    println!("   Captured: {}", handshake.timestamp);
                    println!("   File: {}", handshake.capture_file);
                    println!("   Verified: {}", if handshake.verified { "Yes".green() } else { "No".red() });
                }
            }
        },
        Some(Commands::RealWorldTest { ssid, bssid, channel, interface }) => {
            let interface = interface.clone().unwrap_or_else(|| detect_wifi_interface());
            println!("{} EDUCATIONAL PURPOSES ONLY - DO NOT USE WITHOUT PERMISSION", "[!]".red());
            println!("{} Starting real-world testing on network: {}", "[*]".blue(), ssid);

            let findings = packet_capture::real_world_test(&interface, bssid, ssid, *channel)?;

            println!("{} Testing completed. Results:", "[+]".green());
            if findings.is_empty() {
                println!("{} No vulnerabilities found", "[+]".green());
            } else {
                println!("{} Found {} potential issues:", "[!]".red(), findings.len());
                for (i, finding) in findings.iter().enumerate() {
                    println!("{} {}", format!("[{}]", i+1).red(), finding);
                }
            }
        },
        Some(Commands::VerifyHandshake { capture_file, ssid }) => {
            println!("{} Verifying handshake capture: {}", "[*]".blue(), capture_file);

            let ssid_str = ssid.clone().unwrap_or_else(|| "unknown".to_string());
            let verified = packet_capture::verify_handshake_capture(capture_file, &ssid_str)?;

            if verified {
                println!("{} Handshake is valid", "[+]".green());
            } else {
                println!("{} Handshake is invalid or incomplete", "[!]".red());
            }
        },
        None => {
            println!("{} No command specified. Use --help for usage information.", "[!]".yellow());
        }
    }

    Ok(())
}

fn detect_wifi_interface() -> String {
    // This is a simplified version that works on Windows
    // For a real application, you'd want to implement platform-specific detection
    #[cfg(target_os = "windows")]
    {
        "Wi-Fi".to_string()
    }

    // For Linux systems
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("sh")
            .arg("-c")
            .arg("iw dev | grep Interface | awk '{print $2}'")
            .output()
            .expect("Failed to execute command");

        let interface = str::from_utf8(&output.stdout)
            .unwrap_or("wlan0")
            .trim()
            .to_string();

        if interface.is_empty() {
            "wlan0".to_string()
        } else {
            interface
        }
    }

    // Default fallback
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        "wlan0".to_string()
    }
}

fn scan_networks(_interface: &str) -> Result<Vec<WifiNetwork>> {
    println!("{} Scanning for networks...", "[*]".blue());

    #[cfg(target_os = "windows")]
    let output = Command::new("netsh")
        .args(["wlan", "show", "networks", "mode=Bssid"])
        .output()
        .context("Failed to execute netsh command")?;

    #[cfg(target_os = "linux")]
    let output = Command::new("sudo")
        .args(["iwlist", interface, "scanning"])
        .output()
        .context("Failed to execute iwlist command")?;

    let stdout = str::from_utf8(&output.stdout).context("Failed to parse command output")?;

    parse_scan_output(stdout)
}

fn parse_scan_output(output: &str) -> Result<Vec<WifiNetwork>> {
    let mut networks = Vec::new();

    #[cfg(target_os = "windows")]
    {
        // Windows parsing logic
        let ssid_re = Regex::new(r"SSID \d+ : (.+)").unwrap();
        let bssid_re = Regex::new(r"BSSID \d+\s+: (.+)").unwrap();
        let signal_re = Regex::new(r"Signal\s+: (\d+)%").unwrap();
        let channel_re = Regex::new(r"Channel\s+: (\d+)").unwrap();
        let auth_re = Regex::new(r"Authentication\s+: (.+)").unwrap();

        let mut current_network = WifiNetwork {
            ssid: String::new(),
            bssid: String::new(),
            channel: String::new(),
            signal_strength: String::new(),
            security: String::new(),
        };

        let mut in_network_block = false;

        for line in output.lines() {
            if line.contains("SSID") && ssid_re.is_match(line) {
                if !current_network.ssid.is_empty() {
                    networks.push(current_network.clone());
                }
                current_network = WifiNetwork {
                    ssid: ssid_re.captures(line).unwrap()[1].to_string(),
                    bssid: String::new(),
                    channel: String::new(),
                    signal_strength: String::new(),
                    security: String::new(),
                };
                in_network_block = true;
            } else if in_network_block {
                if line.contains("BSSID") && bssid_re.is_match(line) {
                    current_network.bssid = bssid_re.captures(line).unwrap()[1].to_string();
                } else if line.contains("Signal") && signal_re.is_match(line) {
                    current_network.signal_strength = signal_re.captures(line).unwrap()[1].to_string() + "%";
                } else if line.contains("Channel") && channel_re.is_match(line) {
                    current_network.channel = channel_re.captures(line).unwrap()[1].to_string();
                } else if line.contains("Authentication") && auth_re.is_match(line) {
                    current_network.security = auth_re.captures(line).unwrap()[1].to_string();
                }
            }
        }

        if !current_network.ssid.is_empty() {
            networks.push(current_network);
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Linux parsing logic
        let cell_re = Regex::new(r"Cell \d+ - Address: ([0-9A-F:]+)").unwrap();
        // Using a simpler approach for ESSID
        let channel_re = Regex::new(r"Channel:(\d+)").unwrap();
        let quality_re = Regex::new(r"Quality=(\d+/\d+)").unwrap();
        let encryption_re = Regex::new(r"Encryption key:(on|off)").unwrap();

        let mut current_network = WifiNetwork {
            ssid: String::new(),
            bssid: String::new(),
            channel: String::new(),
            signal_strength: String::new(),
            security: String::new(),
        };

        for line in output.lines() {
            if line.contains("Cell") && cell_re.is_match(line) {
                if !current_network.bssid.is_empty() {
                    networks.push(current_network.clone());
                }
                current_network = WifiNetwork {
                    ssid: String::new(),
                    bssid: cell_re.captures(line).unwrap()[1].to_string(),
                    channel: String::new(),
                    signal_strength: String::new(),
                    security: String::new(),
                };
            } else if line.contains("ESSID") {
                // Extract ESSID using string manipulation instead of regex
                if let Some(start_idx) = line.find("ESSID:\"") {
                    if let Some(end_idx) = line[start_idx..].find("\"") {
                        if let Some(second_quote) = line[start_idx + end_idx + 1..].find("\"") {
                            current_network.ssid = line[start_idx + 7..start_idx + end_idx + 1 + second_quote].to_string();
                        }
                    }
                }
            } else if line.contains("Channel") && channel_re.is_match(line) {
                current_network.channel = channel_re.captures(line).unwrap()[1].to_string();
            } else if line.contains("Quality") && quality_re.is_match(line) {
                current_network.signal_strength = quality_re.captures(line).unwrap()[1].to_string();
            } else if line.contains("Encryption key") && encryption_re.is_match(line) {
                let encryption = encryption_re.captures(line).unwrap()[1].to_string();
                current_network.security = if encryption == "on" { "WPA/WPA2" } else { "None" }.to_string();
            }
        }

        if !current_network.bssid.is_empty() {
            networks.push(current_network);
        }
    }

    Ok(networks)
}

fn display_networks(networks: &[WifiNetwork]) {
    if networks.is_empty() {
        println!("{} No networks found", "[!]".yellow());
        return;
    }

    println!("{} Found {} networks:", "[+]".green(), networks.len());
    println!("{:<20} {:<18} {:<8} {:<15} {:<10}", "SSID", "BSSID", "Channel", "Signal", "Security");
    println!("{}", "-".repeat(75));

    for network in networks {
        let security_colored = match network.security.as_str() {
            "None" => network.security.red(),
            _ => network.security.green(),
        };

        println!(
            "{:<20} {:<18} {:<8} {:<15} {:<10}",
            network.ssid,
            network.bssid,
            network.channel,
            network.signal_strength,
            security_colored
        );
    }
}
