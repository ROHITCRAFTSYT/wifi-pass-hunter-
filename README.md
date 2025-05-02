# WiFi Password Retriever

A cross-platform Python utility to retrieve saved WiFi network profiles and their passwords from your computer.

## Features

- 🖥️ **Cross-Platform Support**: Works on Windows, macOS, and Linux
- 🔐 **Password Recovery**: Retrieves passwords for saved WiFi networks
- 📊 **Multiple Output Formats**: Display results as text, CSV, or JSON
- 💾 **Save to File**: Option to save results to a file

## Requirements

- Python 3.6+
- Administrator/root privileges (required to access system password information)

## Installation

Clone this repository:

```bash
git clone https://github.com/rohitcraftsyt/wifi-password-retriever.git
cd wifi-password-retriever
```

No additional dependencies required - uses only the Python standard library.

## Usage

### Basic Usage

```bash
python wifi_password.py
```

This will display all saved WiFi networks and their passwords in a readable text format.

### Advanced Options

```bash
# Output as JSON
python wifi_password.py --format json

# Output as CSV
python wifi_password.py --format csv

# Save results to a file
python wifi_password.py --output wifi_passwords.txt

# Save as JSON to a file
python wifi_password.py --format json --output wifi_passwords.json
```

### Administrator Privileges

For full functionality, run with administrator privileges:

**Windows**:
- Right-click Command Prompt or PowerShell and select "Run as administrator"
- Then run the script

**macOS/Linux**:
```bash
sudo python wifi_password.py
```

## How It Works

The script uses different methods based on the operating system:

- **Windows**: Uses `netsh wlan` commands to list profiles and retrieve passwords
- **macOS**: Uses the `security` command to access the keychain
- **Linux**: Reads NetworkManager connection files (requires sudo)

## Limitations

- On macOS, accessing passwords may trigger a GUI password prompt
- On Linux, sudo access is required to read NetworkManager configuration files
- Some enterprise or complex authentication methods may not be fully supported

## Legal and Ethical Use

This tool is intended for **legitimate use only**, such as:
- Recovering your own forgotten WiFi passwords
- Network auditing with proper authorization
- Educational purposes

**Do not** use this tool to:
- Access passwords without proper authorization
- Perform any activities that violate laws or regulations

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
