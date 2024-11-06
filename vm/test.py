#!/usr/bin/env python3

import os
import json
import sys
import time
import getpass

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from lib import json_test
from const.vm_const import MANDATORY_KEYS, OPTIONAL_KEYS, INTEGER_KEYS, SSH_CONST, SSHD_CONFIG, SSHD_SEARCHSTRING, SSHD_CUSTOMFILE

# Debug to be deleted
config_file = "/home/nije/json-files/create_vm_fixed_ip.json"
ipaddress = "192.168.254.3"

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        functions.end_output_to_shell()
        sys.exit(1)

def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "user": config.get("USER").get("username"),
        "host": config.get("HOST").get("host_ip"),
        "template_id": config.get("TEMPLATE").get("clone_id"),
        "id": config.get("ID").get("id"),
        "name": config.get("NAME").get("name"),
        "disk": config.get("DISK").get("disk"),
        "cores": config.get("CORES").get("cores"),
        "mem": config.get("MEM").get("memory"),
        "balloon": config.get("BALLOON").get("balloon"),
        "driver": config.get("NET_DRIVER").get("driver"),
        "bridge": config.get("BRIDGE").get("bridge"),
        "vlan": config.get("VLAN").get("vlan"),
        "start_at_boot": config.get("START_AT_BOOT").get("boot_start"),
        "ci_username": config.get("CLOUDINIT_USER").get("ci_username"),
        "ci_password": config.get("CLOUDINIT_PW").get("ci_password"),
        "ci_publickey": config.get("CLOUDINIT_PUB_KEY").get("ci_publickey"),
        "ci_network": config.get("CLOUDINIT_NET").get("ci_network"),
        "ci_domain": config.get("CLOUDINIT_DNS_DOMAIN").get("ci_domain"),
        "ci_dns_server": config.get("CLOUDINIT_DNS_SERVER").get("ci_dns_server"),
        "ci_upgrade": config.get("CLOUDINIT_UPGRADE").get("ci_upgrade"),
        "ci_ipaddress": config.get("CLOUDINIT_IP").get("ci_ipaddress"),
        "ci_gwadvalue": config.get("CLOUDINIT_GW").get("ci_gwadvalue"),
        "ci_netmask": config.get("CLOUDINIT_MASK").get("ci_netmask")
    }

def check_conditional_values(values):
    if not values.get("balloon"):
        values["balloon"] = "0"

    if not values.get("start_at_boot"):
        values["start_at_boot"] = "0"

    if not values.get("ci_upgrade"):
       values["ci_upgrade"] = "1"

    ci_network = values.get("ci_network")
    if ci_network in ["dhcp", "static"]:
        if ci_network == "static":
            functions.check_vlan(values)
            functions.check_valid_ip_address(values, "host")
            functions.check_valid_ip_address(values, "gw")
            functions.check_netmask(values)
    else:
        print(f"\033[91m[ERROR]           : Invalid network type '{ci_network}', expected 'dhcp' or 'static'")

    vm_name = values.get("name")
    if not functions.is_valid_hostname(vm_name):
        print(f"\033[91m[ERROR]           : '{vm_name}' is not a valid hostname. Only A-Z, a-z, 0-9 and '-' allowed.\033[0m")
        functions.end_output_to_shell()
        sys.exit(1)




script_directory = os.path.dirname(os.path.abspath(__file__))
print("-------------------------------------------")
print(f"Parameter filename: {config_file}")
print(f"Script directory  : {script_directory}")
print("-------------------------------------------")
print("")
print("-------------------------------------------")
print("--        Validate JSON structure        --")
print("-------------------------------------------")

config = load_config(config_file)
values = get_json_values(config)
# Use json_test to validate JSON structure
json_test.check_parameters(config, MANDATORY_KEYS, OPTIONAL_KEYS)

print("-------------------------------------------")
print("--          Validate JSON values         --")
print("-------------------------------------------")
# Validate JSON values to ensure proper types
json_test.check_values(config, integer_keys=INTEGER_KEYS)

print("-------------------------------------------")
print("-- Validate JSON conditions and build VM --")
print("-------------------------------------------")
check_conditional_values(values)

import os
import getpass

# Login as the user cloud-init should have created
ci_username = values.get("ci_username")
ci_password = values.get("ci_password")  # Retrieve the cloud-init password correctly
# ci_password = getpass.getpass(f"Enter current password for user '{ci_username}': ")
os.environ["CI_PASSWORD"] = ci_password
ssh = functions.ssh_connect(ipaddress, ci_username)

functions.change_remote_password(ssh, ci_username, ci_password)

sys.exit(1)

# Change the password of ci_username
try:
    # Prompt for the new password and store it in an environment variable
    new_password = getpass.getpass(f"Enter new password for user '{ci_username}': ")
    os.environ["NEW_PASSWORD"] = new_password

    # Verify that the passwords are set in environment variables
    if not os.environ["NEW_PASSWORD"]:
        raise EnvironmentError("\033[91m[ERROR]           : The environment variable 'NEW_PASSWORD' is not set\033[0m")

    if not os.environ["CI_PASSWORD"]:
        raise EnvironmentError("\033[91m[ERROR]           : The environment variable 'CI_PASSWORD' is not set\033[0m")

    # Construct the command to change the password
    # Make sure to properly format the string and include the environment variable correctly
    sudo_command = f"echo {ci_password} | sudo -S -p '' bash -c \"echo '{ci_username}:{new_password}' | chpasswd\""
    print(f"[INFO] Command to be executed: {sudo_command}")  # Print the command for debugging purposes (remove in production)

    # Execute the sudo command
    stdin, stdout, stderr = ssh.exec_command(sudo_command)

    # No need to write password again here; it is piped via the command

    # Get the command's exit status and output
    exit_status = stdout.channel.recv_exit_status()
    output = stdout.read().decode().strip()
    error_output = stderr.read().decode().strip()

    # Handle command errors
    if exit_status != 0:
        print(f"\033[91m[ERROR]           : Failed to change password on {ci_username}: {error_output}\033[0m")
        sys.exit(1)

    print(f"\033[92m[SUCCESS]         : Password for user '{ci_username}' has been changed successfully.")

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    # Remove the NEW_PASSWORD from environment variables
    os.environ.pop("NEW_PASSWORD", None)
    if ssh:
        ssh.close()

def change_remote_password(ssh, sudo_env, new_password, ci_username):

    new_password = os.getenv(new_password)

    if not sudo_password:
        raise EnvironmentError("The environment variable 'CI_PASSWORD' is not set. Please set it before running the script.")

    if not new_password:
        raise EnvironmentError("The environment variable 'NEW_PASSWORD' is not set. Please set it before running the script.")

    # Construct the sudo command with the password
    #command = f"echo '{ci_username}:{new_password}' | sudo chpasswd"
    #sudo_command = f'echo {sudo_password} | sudo -S -p "" bash -c "{command}"'
    #sudo_command = echo password | sudo -S -p "" bash -c "echo 'pch:password1' | chpasswd"



    try:
        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command.

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            print(f"\033[91m[ERROR]           : Failed to change password on {ci_username}: {error_output}\033[0m")
            sys.exit(1)

        return output

    except Exception as e:
        print(f"An unexpected error occurred while executing the command: {e}")
        sys.exit(1)
