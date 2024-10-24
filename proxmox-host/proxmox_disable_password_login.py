#!/usr/bin/env python3

import json
import sys
import paramiko
import time

print("-------------------------------------------")
print("--         Disabled PW SSH login         --")
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
        "pve_sshkey": config.get("PVE_SSHKEY").get("publickey")
    }

def disable_password(values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")

    """Check and modify the SSH configuration to disable password-based login."""
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt to connect using the SSH public key
        ssh.connect(hostname=pve_hostip, username=pve_username)

        # Check if /etc/ssh/sshd_config contains the exact Include directive
        check_include = 'grep -Fxq "Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config && echo "yes" || echo "no"'
        stdin, stdout, stderr = ssh.exec_command(check_include)
        include_found = stdout.read().decode().strip()

        # Parameters to be added
        params = [
            "PasswordAuthentication no",
            "ChallengeResponseAuthentication no",
            "PermitEmptyPasswords no",
            "ClientAliveInterval 3600",
            "ClientAliveCountMax 2",
            "X11Forwarding no",
            "PermitRootLogin prohibit-password"
        ]

        if include_found == "yes":
            print("\033[92m[INFO]            : Include directive is present in /etc/ssh/sshd_config.")

            # Create or overwrite /etc/ssh/sshd_config.d/disable_user_password_ssh.conf with correct parameters
            config_file = "/etc/ssh/sshd_config.d/disable_user_password_ssh.conf"
            create_config = f"echo '# SSH configuration to disable user password SSH login' > {config_file};"
            for param in params:
                create_config += f" echo '{param}' >> {config_file};"
            ssh.exec_command(create_config)
            print(f"\033[92m[INFO]            : Created {config_file} with the necessary parameters.")

            # Remove conflicting parameters from other .conf files, excluding disable_user_password_ssh.conf
            for param in params:
                key = param.split()[0]
                ssh.exec_command(f"find /etc/ssh/sshd_config.d/ -type f ! -name 'disable_user_password_ssh.conf' -exec sed -i '/^\\s*{key}\\s\\+/d' {{}} \\;")

            # Remove conflicting parameters from /etc/ssh/sshd_config
            for param in params:
                key = param.split()[0]
                ssh.exec_command(f"sed -i '/^\\s*{key}\\s\\+/d' /etc/ssh/sshd_config")

            print("\033[92m[INFO]            : Removed conflicting parameters from /etc/ssh/sshd_config and other .conf files, except disable_user_password_ssh.conf.")

        else:
            print("\033[91m[INFO]            : Include directive not found in /etc/ssh/sshd_config.")

            # If Include directive is not found, modify /etc/ssh/sshd_config directly
            for param in params:
                key, value = param.split()
                set_param_cmd = f"if grep -qE '^\\s*{key}\\s+' /etc/ssh/sshd_config; then sed -i 's|^\\s*{key}\\s\\+.*|{param}|g' /etc/ssh/sshd_config; else echo '{param}' >> /etc/ssh/sshd_config; fi"
                ssh.exec_command(set_param_cmd)

            print("\033[92m[INFO]            : Set correct parameters directly in /etc/ssh/sshd_config.")

        # Restart SSH service to apply changes
        restart_ssh = "systemctl restart sshd"
        stdin, stdout, stderr = ssh.exec_command(restart_ssh)
        time.sleep(2)  # Allow time for restart
        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()

        if "failed" not in stderr_output:
            print("\033[92m[INFO]            : SSH service restarted successfully.")
        else:
            print(f"\033[91m[ERROR]           : Failed to restart SSH service. {stderr_output}")

        # Close the SSH connection
        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to Proxmox host via SSH: {e}")
        end_output_to_shell()
        sys.exit(1)

def check_ssh_key(values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")
    pve_sshkey = values.get("pve_sshkey")

    """Check the hostname of the Proxmox host via SSH using key authentication."""
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt to connect using the SSH public key
        ssh.connect(hostname=pve_hostip, username=pve_username)

        # Check if the SSH key is in the authorized_keys file
        check_key = f'grep -Fxq "{pve_sshkey}" ~/.ssh/authorized_keys && echo "yes" || echo "no"'
        stdin, stdout, stderr = ssh.exec_command(check_key)

        if stdout.read().decode().strip() == "yes":
            print(f"\033[92m[INFO]            : Public key found in authorized_keys. Proceeding with sshd change.")
            disable_password(values)
        else:
            print(f"\033[91m[INFO]            : Public key NOT found in authorized_keys. Adding key.")
            add_key = f'echo "{pve_sshkey}" >> ~/.ssh/authorized_keys'
            ssh.exec_command(add_key)

            # Recheck if the SSH key was added successfully
            check_key = f'grep -Fxq "{pve_sshkey}" ~/.ssh/authorized_keys && echo "yes" || echo "no"'
            stdin, stdout, stderr = ssh.exec_command(check_key)
            if stdout.read().decode().strip() == "yes":
                print(f"\033[92m[INFO]            : Public key found in authorized_keys. Proceeding with sshd change.")
                disable_password(values)
            else:
                print(f"\033[91m[ERROR]           : Failed to add the public key to authorized_keys.")

        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to Proxmox host via SSH: {e}")
        end_output_to_shell()
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: check_spaces.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    values = get_json_values(config)
    check_ssh_key(values)
    end_output_to_shell()
