#!/usr/bin/env python3

import json
import sys
import paramiko
import time

print("-------------------------------------------")
print("--        Check Proxmox hostname         --")
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
        "pve_name": config.get("PVE_NAME").get("hostname"),
        "pve_domain": config.get("PVE_DOMAIN").get("domain_string")
    }

def check_hostname(values):
  pve_hostname = values.get("pve_name")
  pve_hostip = values.get("pve_host")
  pve_username = values.get("pve_user")
  pve_domain = values.get("pve_domain")

  print(f"\033[92m[INFO]            : Expected hostname'{pve_hostname}'.")
  """Check the hostname of the Proxmox host via SSH using key authentication."""
  try:
      # Create an SSH client
      ssh = paramiko.SSHClient()
      ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

      # Attempt to connect using the SSH public key
      ssh.connect(hostname=pve_hostip, username=pve_username)

      # Execute the command to get the current hostname
      stdin, stdout, stderr = ssh.exec_command('hostname')
      current_hostname = stdout.read().decode().strip()

      print(f"\033[92m[INFO]            : Current hostname '{current_hostname}'.")

      if current_hostname == pve_hostname:
          print(f"\033[92m[SUCCESS]         : Hostname matches the expected value.")
      else:
          print(f"\033[92m[INFO]            : Hostname mismatch! Expected '{pve_hostname}', but got '{current_hostname}'.")
          fqdn = f"{pve_hostname}.{pve_domain}"
        # Check if Proxmox node is empty
          check_cmd = (
              "[ -z \"$(ls -A /etc/pve/nodes/{current_hostname}/lxc 2>/dev/null)\" ] && "
              "[ -z \"$(ls -A /etc/pve/nodes/{current_hostname}/qemu-server 2>/dev/null)\" ]"
          )
          stdin, stdout, stderr = ssh.exec_command(check_cmd)
          if stdout.read().decode().strip() == "":
              print(f"\033[92m[INFO]            : Proxmox node is empty. Proceeding with hostname change.")

              # Perform the hostname change on the remote host
              change_cmd = f"""
              echo "{pve_hostname}" > /etc/hostname
              sed -i "/{current_hostname}/d" /etc/hosts
              echo "{pve_hostip} {fqdn} {pve_hostname}" >> /etc/hosts
              hostnamectl set-hostname "{pve_hostname}"
              reboot
              """
              stdin, stdout, stderr = ssh.exec_command(change_cmd)
              stdout.channel.recv_exit_status()  # Wait for command to complete
              print(f"\033[92m[SUCCESS]         : Hostname on {pve_hostip} has been changed from {current_hostname} to {fqdn}")

              # Wait for the system to reboot
              print(f"\033[92m[INFO]            : Waiting 120 seconds for the system to reboot...")
              time.sleep(120)  # Wait for 120 seconds before rechecking

              # Recheck the hostname after reboot
              print(f"\033[92m[INFO]            : Rechecking hostname after reboot...")
              check_hostname(values)  # Re-check the hostname

          else:
              print(f"\033[91m[ERROR]           : Proxmox node is not empty. Cannot change hostname.")
              exit(1)

      ssh.close()

      # Close the SSH connection
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
    check_hostname(values)
    end_output_to_shell()