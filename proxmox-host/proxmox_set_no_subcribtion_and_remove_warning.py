#!/usr/bin/env python3

import json
import sys
import paramiko


print("-------------------------------------------")
print("--       Setting pve_no_sucription       --")
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
        "pve_host": config.get("PVE_HOST").get("host_ip")
    }

def set_pve_no_subscription(values):
    pve_hostip = values.get("pve_host")
    pve_username = values.get("pve_user")

    """Check and modify the pve_no_subscription setting."""
    try:
        # Create an SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Attempt to connect using the SSH public key
        ssh.connect(hostname=pve_hostip, username=pve_username)

        # Step 1: Check if the pve-no-subscription repository is enabled or commented
        check_repo_cmd = 'grep -q "^deb .*pve-no-subscription" /etc/apt/sources.list && echo "enabled" || grep -q "^# deb .*pve-no-subscription" /etc/apt/sources.list && echo "commented" || echo "not_found"'
        stdin, stdout, stderr = ssh.exec_command(check_repo_cmd)

        result = stdout.read().decode().strip()

        if result == "enabled":
            print("\033[92m[INFO]            : pve-no-subscription repository is already enabled.")

        elif result == "commented":
            print("\033[91m[INFO]            : pve-no-subscription repository is found but not enabled. Enabling it now...")
            # Step 2: Enable the pve-no-subscription repository (uncomment it)
            enable_repo_cmd = "sed -i 's/^# deb \\(.*pve-no-subscription\\)/deb \\1/' /etc/apt/sources.list"
            ssh.exec_command(enable_repo_cmd)
            print(f"\033[92m[SUCCESS]         : pve-no-subscription repository has been enabled.")

        elif result == "not_found":
            print("\033[91m[INFO]            : pve-no-subscription repository not found. Adding it now...")
            # Step 3: Add the pve-no-subscription repository to sources.list
            add_repo_cmd = 'echo "deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription" | tee -a /etc/apt/sources.list > /dev/null'
            ssh.exec_command(add_repo_cmd)
            print(f"\033[92m[SUCCESS]         : pve-no-subscription repository has been added to /etc/apt/sources.list.")

        # Step 4: Check and disable enterprise repository if not already disabled
        check_enterprise_repo_cmd = 'grep -q "^deb .*bookworm pve-enterprise" /etc/apt/sources.list.d/pve-enterprise.list && echo "enabled" || echo "disabled"'
        stdin, stdout, stderr = ssh.exec_command(check_enterprise_repo_cmd)
        enterprise_result = stdout.read().decode().strip()

        if enterprise_result == "enabled":
            print("\033[91m[INFO]            : Enterprise repository is enabled. Disabling it now by commenting it out...")
            disable_enterprise_repo_cmd = r"sed -i 's/^\(deb .*bookworm pve-enterprise\)/# \1/' /etc/apt/sources.list.d/pve-enterprise.list"
            ssh.exec_command(disable_enterprise_repo_cmd)
            print(f"\033[92m[SUCCESS]         : Enterprise repository has been disabled by commenting it out.")
        else:
            print("\033[92m[INFO]            : Enterprise repository is already disabled.")

        # Step 5: Comment out Ceph-related entries in ceph.list
        check_ceph_list_cmd = 'grep -q "^deb .*ceph-quincy bookworm enterprise" /etc/apt/sources.list.d/ceph.list && echo "enabled" || echo "disabled"'
        stdin, stdout, stderr = ssh.exec_command(check_ceph_list_cmd)
        ceph_list_result = stdout.read().decode().strip()

        if ceph_list_result == "enabled":
            print("\033[91m[INFO]            : ceph.list found. Commenting out ceph-quincy, bookworm, or enterprise entries...")
            comment_ceph_entries_cmd = r"sed -i 's/^\(deb .*bookworm enterprise\)/# \1/' /etc/apt/sources.list.d/ceph.list"
            ssh.exec_command(comment_ceph_entries_cmd)
            print(f"\033[92m[SUCCESS]         : Ceph-related entries have been commented out in ceph.list.")
        else:
            print("\033[92m[INFO]            : ceph.list is already disabled.")

        # Step 6: Apply pve-no-subscription patch
        print("\033[92m[INFO]            : Attempting pve-no-subscription patch...")

        file_path = '/usr/share/perl5/PVE/API2/Subscription.pm'
        find_str = 'NotFound'
        replace_str = 'Active'

        # Check if the file exists
        check_file_cmd = f'test -f "{file_path}" && echo "exists" || echo "not_exists"'
        stdin, stdout, stderr = ssh.exec_command(check_file_cmd)
        file_exists = stdout.read().decode().strip()

        if file_exists == "not_exists":
            print(f"\033[91m[ERROR]           : {file_path} does not exist! Are you sure this is PVE?")
            ssh.close()
            sys.exit(1)
        else:
            # Check if the file contains 'NotFound'
            check_find_cmd = f'grep -i "{find_str}" "{file_path}" && echo "found" || echo "not_found"'
            stdin, stdout, stderr = ssh.exec_command(check_find_cmd)
            find_result = stdout.read().decode().strip()

            if find_result == "not_found":
                print(f"\033[92m[INFO]            : PVE appears to be patched.")
            else:
                # Apply the patch (replace 'NotFound' with 'Active')
                print(f"\033[92m[INFO]            : Applying pve-no-subscription patch in {file_path}...")
                apply_patch_cmd = f'sed -i "s/{find_str}/{replace_str}/gi" "{file_path}"'
                ssh.exec_command(apply_patch_cmd)

                # Restart the services
                print(f"\033[92m[INFO]            : Restarting services...")
                ssh.exec_command('systemctl restart pvedaemon')
                ssh.exec_command('systemctl restart pveproxy')

                print(f"\033[92m[SUCCESS]         : Subscription updated from {find_str} to {replace_str}.")


        # Close the SSH connection
        ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error connecting to Proxmox host via SSH: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\033[91m[ERROR]           : Usage: check_spaces.py <config.json>")
        end_output_to_shell()
        sys.exit(1)

    config_file = sys.argv[1]
    config = load_config(config_file)
    values = get_json_values(config)
    set_pve_no_subscription(values)
    end_output_to_shell()