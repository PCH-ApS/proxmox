#!/usr/bin/env python3

import json
import sys
import os

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now you can import the module from lib
from lib import functions
from lib import json_test
from const.template_const import MANDATORY_KEYS, OPTIONAL_KEYS, INTEGER_KEYS

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
        "id": config.get("ID").get("id"),
        "name": config.get("NAME").get("name"),
        "cores": config.get("CORES").get("cores"),
        "mem": config.get("MEMORY").get("mem"),
        "storage_ctrl": config.get("STORAGE_CONTROLLER").get("storage_ctrl"),
        "local_storage": config.get("LOCAL_STORAGE").get("local_storage"),
        "nic": config.get("NETWORK_CONTROLLER").get("nic"),
        "bridge": config.get("NETWORK_BRIDGE").get("bridge"),
        "image": config.get("DISKIMAGE").get("image")
    }

def check_template_id_in_use(ssh, values):
    template_id = values.get("id")
    """Check if TEMPLATE_ID is already in use on the Proxmox host"""
    stdin, stdout, stderr = ssh.exec_command(f"qm list | awk '{{print $1}}' | grep -q '^{template_id}$' && echo 'in_use' || echo 'not_in_use'")
    result = stdout.read().decode().strip()
    if result == "in_use":
        print(f"\033[91m[ERROR]           : TEMPLATE_ID '{template_id}' is already in use on the Proxmox host.")
        sys.exit(1)
    print(f"\033[92m[SUCCESS]         : TEMPLATE_ID '{template_id}' is not in use on the Proxmox host.")

def check_bridge_exists(ssh, values):
    bridge = values.get("bridge")
    """Check if the bridge exists and is active on the Proxmox host"""
    stdin, stdout, stderr = ssh.exec_command(f"brctl show | grep -w '{bridge}'")
    if not stdout.read().decode().strip():
        print(f"\033[91m[ERROR]           : TEMPLATE_BRIDGE '{bridge}' does not exist or is not active on the Proxmox host.")
        sys.exit(1)
    print(f"\033[92m[SUCCESS]         : TEMPLATE_BRIDGE '{bridge}' exists and is active.")

def check_storage_exists(ssh, values):
    local_storage = values.get("local_storage")
    """Check if the storage exists on the Proxmox host"""
    stdin, stdout, stderr = ssh.exec_command(f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'")
    if not stdout.read().decode().strip():
        print(f"\033[91m[ERROR]           : TEMPLATE_STORAGE '{local_storage}' does not exist on the Proxmox host.")
        sys.exit(1)
    print(f"\033[92m[SUCCESS]         : TEMPLATE_STORAGE '{local_storage}' exists on the Proxmox host.")

def create_template(ssh, values):
    """Create the server template on the Proxmox host."""
    try:
        template_id = values.get("id")
        commands = [
            f"qm create {template_id} --name {values['name']}",  # Create VM template with name
            f"qm set {template_id} --cpu host",  # Set CPU type
            f"qm set {template_id} --cores {values['cores']}",  # Set number of CPU cores
            f"qm set {template_id} --memory {values['mem']}",  # Set memory allocation
            f"qm set {template_id} --scsihw {values['storage_ctrl']}",  # Set storage controller
            f"qm set {template_id} --scsi0 {values['local_storage']}:0,import-from={values['image']},discard=on",  # Set disk image
            f"qm set {template_id} --ide2 {values['local_storage']}:cloudinit",  # Configure cloud-init drive
            f"qm set {template_id} --net0 model={values['nic']},bridge={values['bridge']}",  # Set network model and bridge
            f"qm set {template_id} --boot c --bootdisk scsi0",  # Configure boot device
            f"qm set {template_id} --boot order=scsi0",  # Set boot order
            f"qm set {template_id} --agent enabled=1,fstrim_cloned_disks=1",  # Enable guest agent
            f"qm set {template_id} --serial0 socket",  # Configure serial console
            f"qm set {template_id} --vga serial0",  # Set VGA configuration
            f"qm template {template_id}"  # Convert VM into a template
        ]

        # Execute each command via SSH
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for command to complete
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"\033[91m[ERROR]           : Command '{command}' failed with error: {error_output}")
                sys.exit(1)
            else:
                print(f"\033[92m[SUCCESS]         : Command '{command}' executed successfully.")

        print(f"\033[92m[SUCCESS]         : Server template '{template_id}' created successfully on the Proxmox host.")
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to create server template: {e}")
        sys.exit(1)

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
print("--             Build template            --")
print("-------------------------------------------")

ssh = functions.ssh_connect(values.get("host"), values.get("user"))

# Create and configure the VM
create_template(ssh, values)
ssh.close()

functions.end_output_to_shell()