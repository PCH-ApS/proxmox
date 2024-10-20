#!/usr/bin/env python3

import json
import sys
import paramiko

print("-------------------------------------------")
print("--          Importing ISO images         --")
print("-------------------------------------------")

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        end_output_to_shell()
        sys.exit(1)

def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "pve_user": config.get("PVE_USER").get("username"),
        "pve_host": config.get("PVE_HOST").get("host_ip"),
        "pve_iso": config.get("PVE_ISO").get("urls")
    }

def download_iso(values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")
    pve_iso_urls = values.get("pve_iso")  # Correct access to 'pve_iso' key

    if not pve_iso_urls:
        print(f"\033[91m[ERROR]           : No ISO URLs provided in the configuration file.")
        sys.exit(1)

    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt to connect using the SSH public key
        ssh.connect(hostname=pve_hostip, username=pve_username)

        # Step 1: Ensure the directory exists
        print(f"\033[92m[INFO]            : Ensuring /var/lib/vz/template/iso exists on the remote host...")
        ssh.exec_command("mkdir -p /var/lib/vz/template/iso")

        # Step 2: Check if each ISO image already exists and download if not
        for url in pve_iso_urls:
            iso_filename = url.split('/')[-1]
            iso_filepath = f"/var/lib/vz/template/iso/{iso_filename}"

            # Check if the file already exists on the remote host
            check_file_cmd = f"test -f {iso_filepath} && echo 'exists' || echo 'not_exists'"
            stdin, stdout, stderr = ssh.exec_command(check_file_cmd)
            file_exists = stdout.read().decode().strip()

            if file_exists == "exists":
                print(f"\033[93m[INFO]            : {iso_filename} already exists, skipping download.")
            else:
                print(f"\033[92m[INFO]            : Downloading {iso_filename} to /var/lib/vz/template/iso...")

                # Execute wget and wait for it to complete
                download_cmd = f"wget -q -P /var/lib/vz/template/iso {url}"
                stdin, stdout, stderr = ssh.exec_command(download_cmd)

                # Wait for the command to complete and check if any errors occurred
                exit_status = stdout.channel.recv_exit_status()  # Wait for the command to finish
                if exit_status == 0:
                    print(f"\033[92m[SUCCESS]         : {iso_filename} has been successfully downloaded.")
                else:
                    error_message = stderr.read().decode().strip()
                    print(f"\033[91m[ERROR]           : Failed to download {iso_filename}. Error: {error_message}")

        # Close the SSH connection
        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to Proxmox host via SSH: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: script.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    values = get_json_values(config)
    download_iso(values)
    end_output_to_shell()
