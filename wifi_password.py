#!/usr/bin/env python3
"""WiFi Password Retriever.

Retrieves WiFi network profiles and their passwords that are **already saved on
this machine**, for the current user/administrator. Cross-platform support for
Windows, macOS and Linux.

This reads secrets that the operating system already stores for you; it is
intended for recovering your own saved credentials. Handle the output
accordingly — passwords are sensitive.
"""

import argparse
import csv
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
from typing import Dict, List


def _run(cmd, **kwargs) -> str:
    """Run a command and return stdout as text, or '' on failure.

    Never uses ``shell=True``; arguments are always passed as a list so that
    network names containing shell metacharacters cannot lead to command
    injection (CWE-78).
    """
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, universal_newlines=True, **kwargs
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return ""


def get_windows_wifi_passwords() -> List[Dict[str, str]]:
    """Retrieve saved WiFi passwords on Windows via netsh."""
    networks_data = _run(['netsh', 'wlan', 'show', 'profiles'])
    if not networks_data:
        print("Error: unable to run 'netsh wlan show profiles'. "
              "Make sure WLAN AutoConfig is running and you have permission.")
        return []

    # Profile names can contain spaces and colons; capture the remainder of the
    # line and strip it. Works across localized "All User Profile" lines.
    profile_names = [m.strip() for m in re.findall(r"All User Profile\s*:\s*(.+)", networks_data)]

    wifi_list: List[Dict[str, str]] = []
    for name in profile_names:
        info = {"ssid": name, "password": "No password set or unable to retrieve"}
        result = _run(['netsh', 'wlan', 'show', 'profile', f'name={name}', 'key=clear'])
        match = re.search(r"Key Content\s*:\s*(.+)", result)
        if match:
            info["password"] = match.group(1).strip()
        wifi_list.append(info)
    return wifi_list


def _macos_wifi_interface() -> str:
    """Return the Wi-Fi hardware interface (e.g. en0), or '' if not found."""
    ports = _run(['networksetup', '-listallhardwareports'])
    # Blocks look like: "Hardware Port: Wi-Fi\nDevice: en0\n..."
    match = re.search(r"Hardware Port:\s*Wi-Fi\s*\nDevice:\s*(\w+)", ports)
    return match.group(1) if match else ""


def get_macos_wifi_passwords() -> List[Dict[str, str]]:
    """Retrieve *saved* WiFi passwords on macOS.

    Uses ``networksetup`` to list preferred (saved) networks and the keychain to
    read each password. This replaces the removed/deprecated ``airport`` binary
    and, importantly, enumerates *saved* networks rather than networks currently
    in range.
    """
    interface = _macos_wifi_interface()
    if not interface:
        print("Error: could not determine the Wi-Fi interface via networksetup.")
        return []

    listing = _run(['networksetup', '-listpreferredwirelessnetworks', interface])
    ssids = [line.strip() for line in listing.splitlines()[1:] if line.strip()]

    wifi_list: List[Dict[str, str]] = []
    for ssid in ssids:
        info = {"ssid": ssid, "password": "No password found or unable to retrieve"}
        # find-generic-password will prompt for keychain access via the GUI.
        password = _run(['security', 'find-generic-password', '-D',
                         'AirPort network password', '-a', ssid, '-w']).strip()
        if password:
            info["password"] = password
        wifi_list.append(info)
    return wifi_list


def get_linux_wifi_passwords() -> List[Dict[str, str]]:
    """Retrieve saved WiFi passwords on Linux (NetworkManager)."""
    conn_dir = '/etc/NetworkManager/system-connections/'
    if not os.path.isdir(conn_dir):
        print(f"Error: {conn_dir} not found (NetworkManager required).")
        return []

    listing = _run(['sudo', 'ls', conn_dir])
    if not listing:
        print("Error: unable to list NetworkManager connections (need sudo).")
        return []

    wifi_list: List[Dict[str, str]] = []
    for filename in (f for f in listing.splitlines() if f.strip()):
        content = _run(['sudo', 'cat', os.path.join(conn_dir, filename)])
        ssid_match = re.search(r"^ssid=(.*)$", content, re.MULTILINE)
        if not ssid_match:
            continue
        psk_match = re.search(r"^psk=(.*)$", content, re.MULTILINE)
        wifi_list.append({
            "ssid": ssid_match.group(1).strip(),
            "password": psk_match.group(1).strip() if psk_match
            else "No password set or unable to retrieve",
        })
    return wifi_list


def get_wifi_passwords() -> List[Dict[str, str]]:
    """Dispatch to the OS-specific retriever."""
    system = platform.system().lower()
    if system == 'windows':
        return get_windows_wifi_passwords()
    if system == 'darwin':
        return get_macos_wifi_passwords()
    if system == 'linux':
        return get_linux_wifi_passwords()
    print(f"Error: Unsupported operating system: {system}")
    return []


def _sanitize_csv_field(value: str) -> str:
    """Neutralize spreadsheet formula injection (CWE-1236).

    A leading =, +, -, @, tab or CR can be interpreted as a formula by Excel /
    Sheets. Prefix such values with a single quote so they render as text. The
    csv module still handles quoting/escaping of commas and quotes.
    """
    if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


def format_wifi_info(wifi_list: List[Dict[str, str]], output_format: str = "text") -> str:
    """Render the results to a string in the requested format."""
    if not wifi_list:
        return "No WiFi profiles found or unable to retrieve passwords."

    if output_format == "json":
        return json.dumps(wifi_list, indent=2)

    if output_format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
        writer.writerow(["SSID", "Password"])
        for wifi in wifi_list:
            writer.writerow([
                _sanitize_csv_field(wifi["ssid"]),
                _sanitize_csv_field(wifi["password"]),
            ])
        return buf.getvalue().rstrip("\n")

    # text
    lines = ["", "WiFi Profiles and Passwords:", "-" * 50]
    for wifi in wifi_list:
        lines.append(f"SSID: {wifi['ssid']}")
        lines.append(f"Password: {wifi['password']}")
        lines.append("-" * 50)
    return "\n".join(lines)


def _write_secure(path: str, data: str) -> None:
    """Write ``data`` to ``path`` with owner-only (0600) permissions.

    The file is created restrictively from the start so the plaintext passwords
    are never briefly world-readable on disk (CWE-276).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(data)
            if not data.endswith("\n"):
                f.write("\n")
    finally:
        # Best-effort tightening on platforms where mode wasn't applied at creation.
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    if os.name == 'nt':
        # POSIX mode bits don't create owner-only ACLs on Windows. Break
        # inheritance and grant Full control only to the current user.
        user = os.environ.get('USERNAME')
        if user:
            subprocess.run(['icacls', path, '/inheritance:r',
                            '/grant:r', f'{user}:F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _perms_note() -> str:
    """Human-readable description of the restriction actually applied."""
    return ("permissions restricted to your user account" if os.name == 'nt'
            else "permissions restricted to owner (0600)")


def _has_admin() -> bool:
    if os.name == 'nt':
        return subprocess.run(['net', 'session'], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def main():
    parser = argparse.ArgumentParser(description="Retrieve saved WiFi passwords")
    parser.add_argument("--format", choices=["text", "csv", "json"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output", help="Write results to this file (mode 0600)")
    args = parser.parse_args()

    if not _has_admin():
        print("Warning: administrative privileges may be required to retrieve all "
              "passwords. Try running as Administrator (Windows) or with sudo "
              "(macOS/Linux).", file=sys.stderr)

    wifi_list = get_wifi_passwords()
    rendered = format_wifi_info(wifi_list, args.format)

    if args.output:
        try:
            _write_secure(args.output, rendered)
        except OSError as exc:
            print(f"Error writing to file: {exc}", file=sys.stderr)
            return 1
        print(f"Results saved to {args.output} ({_perms_note()}).")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
