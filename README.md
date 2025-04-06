# Wi-Fi Security Testing Tool

A powerful Wi-Fi security testing tool written in Rust that integrates with industry-standard tools like aircrack-ng.

## Disclaimer

This tool is designed for security professionals and network administrators to test the security of their own networks.

**IMPORTANT**: Only use this tool on networks you own or have explicit permission to test. Unauthorized network scanning and testing is illegal in most jurisdictions and can result in severe legal consequences.

## Features

### Network Scanning Features

- Scan for available Wi-Fi networks
- Display detailed network information (SSID, BSSID, channel, signal strength, security)
- Check for security vulnerabilities in wireless networks

### Advanced Security Testing Features

- Put wireless interfaces in monitor mode (supports both Linux and Windows with appropriate drivers)
- Capture and analyze wireless traffic using tcpdump/Wireshark/tshark
- Perform deauthentication attacks to disconnect clients from networks
- Capture WPA handshakes for security analysis
- Crack WPA passwords using dictionary attacks (with built-in cracker and aircrack-ng integration)
- Analyze WPA handshakes and derive encryption keys using PBKDF2 and HMAC-SHA1
- Perform real-world testing to identify common network vulnerabilities
- Test for WPS vulnerabilities, weak cipher suites, and PMKID attacks
- Verify captured handshakes for completeness and validity

## Requirements

- Rust (latest stable version)
- Administrator/root privileges (required for network operations)

### Linux Requirements

- `iw` and `iwconfig` tools for interface management
- `aircrack-ng` suite for advanced features (airmon-ng, airodump-ng, aireplay-ng)
- `tcpdump` for packet capture and analysis

### Windows Requirements

- Compatible wireless adapter that supports monitor mode
- Aircrack-ng for Windows or similar tools
- Wireshark/tshark for packet analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/raheesahmed/wifi_scanner.git
cd wifi_scanner

# Build the project
cargo build --release

# The binary will be available at target/release/wifi_scanner
```

## Usage

### Basic Commands

```bash
# Scan for available networks (auto-detect interface)
wifi_scanner scan

# Specify a wireless interface
wifi_scanner scan --interface wlan0

# Check security of a specific network
wifi_scanner security --ssid "NetworkName" --bssid "00:11:22:33:44:55"
```

### Advanced Commands

```bash
# Enable monitor mode on an interface
wifi_scanner monitor-mode --interface wlan0

# Disable monitor mode
wifi_scanner monitor-mode --interface wlan0 --disable

# Monitor wireless traffic for 60 seconds
wifi_scanner monitor-traffic --interface wlan0 --duration 60

# Perform a deauthentication attack
wifi_scanner deauth --bssid "00:11:22:33:44:55" --client "AA:BB:CC:DD:EE:FF" --count 5

# Broadcast deauth (disconnect all clients)
wifi_scanner deauth --bssid "00:11:22:33:44:55" --count 10

# Capture a WPA handshake
wifi_scanner capture-handshake --bssid "00:11:22:33:44:55" --channel 6

# List all captured handshakes
wifi_scanner list-handshakes

# Verify a captured handshake
wifi_scanner verify-handshake --capture-file "captures/handshake_001122334455.cap" --ssid "NetworkName"

# Perform real-world testing on a network
wifi_scanner real-world-test --ssid "NetworkName" --bssid "00:11:22:33:44:55" --channel 6

# Crack a WPA password using a dictionary attack
wifi_scanner crack-wpa --ssid "NetworkName" --bssid "00:11:22:33:44:55" --wordlist wordlist.txt

# Run a demonstration of WPA cracking with a known password
wifi_scanner demo-wpa-crack --password "mypassword"

# Start the web UI on port 8080
wifi_scanner web-ui --port 8080
```

## Legal and Ethical Considerations

- Always obtain explicit permission before scanning or testing any network
- Only use this tool on networks you own or have permission to test
- Be aware of local laws regarding network security testing
- Document all testing activities and maintain proper authorization records
- Follow responsible disclosure practices if vulnerabilities are found

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Technical Details

### WPA/WPA2 Security

This tool demonstrates several aspects of WPA/WPA2 security:

1. **4-Way Handshake**: The tool simulates capturing and analyzing the WPA 4-way handshake, which is the authentication process used in WPA/WPA2 networks.

2. **PBKDF2 Key Derivation**: The tool implements the PBKDF2 function used to derive the PMK (Pairwise Master Key) from the passphrase and SSID.

3. **PTK Calculation**: The tool demonstrates how the PTK (Pairwise Transient Key) is calculated from the PMK, AP MAC, client MAC, ANonce, and SNonce.

4. **Dictionary Attacks**: The tool shows how dictionary attacks can be performed against captured WPA handshakes.

### Deauthentication Attacks

The tool simulates deauthentication attacks, which are used to disconnect clients from a network by sending spoofed deauthentication frames. This is often used to force clients to reconnect, allowing the capture of the WPA handshake.

### Monitor Mode

The tool demonstrates how to put wireless interfaces into monitor mode, which allows capturing all wireless frames without being associated with a network.

## Learning Resources

If you're interested in learning more about network security and ethical hacking, consider these resources:

- [Certified Ethical Hacker (CEH)](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/)
- [SANS Institute](https://www.sans.org/)
- [Offensive Security](https://www.offensive-security.com/)
- [Rust Programming Language Book](https://doc.rust-lang.org/book/)
- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [WiFi Security: WEP, WPA, and WPA2](https://www.sans.org/white-papers/33343/)
- [IEEE 802.11 Standards](https://standards.ieee.org/standard/802_11-2016.html)
