#!/usr/bin/env python3

import os
import json
import sys
import time

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from lib import json_test
from const.host_const import MANDATORY_KEYS, OPTIONAL_KEYS

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
        "pve_user": config.get("PVE_USER").get("username"),
        "pve_host": config.get("PVE_HOST").get("host_ip"),
        "pve_name": config.get("PVE_NAME").get("hostname"),
        "pve_domain": config.get("PVE_DOMAIN").get("domain_string"),
        "pve_sshkey": config.get("PVE_SSHKEY").get("publickey"),
        "pve_iso": config.get("PVE_ISO").get("urls")
    }

config_file = sys.argv[1]
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
print("--        Configure PROXMOX host         --")
print("-------------------------------------------")

# Establish SSH connection to Proxmox server
ssh = functions.ssh_connect(values.get("host"), values.get("user"))



# Create and configure the VM
create_server(ssh, values)
create_ci_options(ssh, values)
create_cloudinit(ssh, values)
start_vm(ssh, values)

# Wait and get the VM's IPv4 address
ipaddress = get_vm_ipv4_address(ssh, values)
temp_fix_cloudinit(ssh, values)
ssh.close()

# login as the local default user
ssh = functions.ssh_connect(ipaddress, "ubuntu")
on_guest_temp_fix_cloudinit(ssh, values, ipaddress)
ssh.close()

# login as user cloud-init shpuld have created
ci_username = values.get("ci_username")
os.environ["CI_PASSWORD"] = values.get("ci_password")
ssh = functions.ssh_connect(ipaddress, ci_username)
on_guest_temp_fix_cloudinit_part_2(ssh, values, ipaddress)
on_guest_configuration(ssh, values, ipaddress)
ssh.close()

functions.end_output_to_shell()