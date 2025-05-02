#!/usr/bin/env python3
"""
WiFi Password Retriever

This script retrieves saved WiFi network profiles and their passwords.
Cross-platform implementation for Windows, macOS, and Linux.
"""

import os
import subprocess
import platform
import re
import sys
import argparse
from typing import Dict, List, Tuple


def get_windows_wifi_passwords() -> List[Dict[str, str]]:
    """Retrieve WiFi passwords on Windows systems."""
    try:
        # Get all WiFi profile names
        networks_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], 
                                             stderr=subprocess.DEVNULL,
                                             universal_newlines=True)
        
        # Extract profile names using regex
        profile_names = re.findall(r"All User Profile\s*: (.*)", networks_data)
        
        wifi_list = []
        
        if not profile_names:
            return wifi_list
            
        for name in profile_names:
            # For each profile, get the password (key content)
            try:
                wifi_info = {}
                wifi_info["ssid"] = name.strip()
                
                # Get password for this profile
                result = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', 
                                              name, 'key=clear'],
                                             stderr=subprocess.DEVNULL,
                                             universal_newlines=True)
                
                # Extract password using regex
                password = re.search(r"Key Content\s*: (.*)", result)
                
                if password:
                    wifi_info["password"] = password.group(1).strip()
                else:
                    wifi_info["password"] = "No password set or unable to retrieve"
                    
                wifi_list.append(wifi_info)
                
            except subprocess.CalledProcessError:
                continue
                
        return wifi_list
        
    except subprocess.CalledProcessError:
        print("Error: Unable to run netsh command. Make sure you have the necessary permissions.")
        return []


def get_macos_wifi_passwords() -> List[Dict[str, str]]:
    """Retrieve WiFi passwords on macOS systems."""
    try:
        # Get all WiFi SSIDs
        airport_cmd = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'
        
        if not os.path.exists(airport_cmd):
            print("Error: airport command not found.")
            return []
            
        networks_data = subprocess.check_output([airport_cmd, '-s'], 
                                            stderr=subprocess.DEVNULL,
                                            universal_newlines=True)
        
        # Extract SSIDs (first column in output)
        ssids = []
        for line in networks_data.split('\n')[1:]:  # Skip header line
            if line.strip():
                ssids.append(line.split()[0])
        
        wifi_list = []
        
        for ssid in ssids:
            try:
                wifi_info = {"ssid": ssid}
                
                # Use security command to extract password
                # Note: This will prompt for admin password via GUI
                cmd = f"security find-generic-password -D 'AirPort network password' -a '{ssid}' -w"
                result = subprocess.check_output(cmd, shell=True, 
                                              stderr=subprocess.DEVNULL,
                                              universal_newlines=True)
                
                if result:
                    wifi_info["password"] = result.strip()
                else:
                    wifi_info["password"] = "No password found or unable to retrieve"
                    
                wifi_list.append(wifi_info)
                
            except subprocess.CalledProcessError:
                # Password might be inaccessible or network not saved
                continue
                
        return wifi_list
        
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return []


def get_linux_wifi_passwords() -> List[Dict[str, str]]:
    """Retrieve WiFi passwords on Linux systems."""
    try:
        # Check if NetworkManager is being used
        if not os.path.exists('/etc/NetworkManager/system-connections/'):
            print("Error: NetworkManager connections directory not found.")
            return []
        
        wifi_list = []
        
        # Need sudo for reading protected NetworkManager connection files
        connection_files = subprocess.check_output(['sudo', 'ls', '/etc/NetworkManager/system-connections/'],
                                              stderr=subprocess.DEVNULL,
                                              universal_newlines=True).split('\n')
        
        for filename in connection_files:
            if not filename:  # Skip empty lines
                continue
                
            try:
                file_path = f'/etc/NetworkManager/system-connections/{filename}'
                content = subprocess.check_output(['sudo', 'cat', file_path],
                                             stderr=subprocess.DEVNULL,
                                             universal_newlines=True)
                
                # Extract SSID and password using regex
                ssid_match = re.search(r"ssid=(.*)", content)
                psk_match = re.search(r"psk=(.*)", content)
                
                if ssid_match:
                    wifi_info = {"ssid": ssid_match.group(1).strip()}
                    
                    if psk_match:
                        wifi_info["password"] = psk_match.group(1).strip()
                    else:
                        wifi_info["password"] = "No password set or unable to retrieve"
                        
                    wifi_list.append(wifi_info)
                    
            except subprocess.CalledProcessError:
                continue
                
        return wifi_list
        
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return []


def get_wifi_passwords() -> List[Dict[str, str]]:
    """Get WiFi passwords based on the current operating system."""
    system = platform.system().lower()
    
    if system == 'windows':
        return get_windows_wifi_passwords()
    elif system == 'darwin':  # macOS
        return get_macos_wifi_passwords()
    elif system == 'linux':
        return get_linux_wifi_passwords()
    else:
        print(f"Error: Unsupported operating system: {system}")
        return []


def display_wifi_info(wifi_list: List[Dict[str, str]], output_format: str = "text") -> None:
    """Display WiFi network information in the specified format."""
    if not wifi_list:
        print("No WiFi profiles found or unable to retrieve passwords.")
        return
        
    if output_format == "text":
        print("\nWiFi Profiles and Passwords:")
        print("-" * 50)
        for wifi in wifi_list:
            print(f"SSID: {wifi['ssid']}")
            print(f"Password: {wifi['password']}")
            print("-" * 50)
            
    elif output_format == "csv":
        print("SSID,Password")
        for wifi in wifi_list:
            print(f"{wifi['ssid']},{wifi['password']}")
            
    elif output_format == "json":
        import json
        print(json.dumps(wifi_list, indent=2))


def main():
    """Main function to parse arguments and retrieve WiFi passwords."""
    parser = argparse.ArgumentParser(description="Retrieve saved WiFi passwords")
    parser.add_argument("--format", choices=["text", "csv", "json"], default="text",
                      help="Output format (default: text)")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    # Check for admin/root privileges
    if os.name == 'nt':  # Windows
        admin = subprocess.run(['net', 'session'], stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL).returncode == 0
    else:  # Unix-like
        admin = os.geteuid() == 0
        
    if not admin:
        print("Warning: This script may require administrative privileges to retrieve all passwords.")
        print("Try running as Administrator (Windows) or with sudo (macOS/Linux).")
    
    # Get WiFi passwords
    wifi_list = get_wifi_passwords()
    
    # Output handling
    if args.output:
        original_stdout = sys.stdout
        try:
            with open(args.output, 'w') as f:
                sys.stdout = f
                display_wifi_info(wifi_list, args.format)
            print(f"Results saved to {args.output}")
        except Exception as e:
            print(f"Error writing to file: {e}")
        finally:
            sys.stdout = original_stdout
    else:
        display_wifi_info(wifi_list, args.format)


if __name__ == "__main__":
    main()