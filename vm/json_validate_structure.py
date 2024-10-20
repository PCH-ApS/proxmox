#!/usr/bin/env python3

import json
import sys

print("-------------------------------------------")
print("--        Validate JSON structure        --")
print("-------------------------------------------")

# Dictionary of mandatory keys and their required first sub-keys
MANDATORY_KEYS = {
    "USER": "username",
    "HOST": "host_ip",
    "TEMPLATE": "clone_id",
    "ID": "id",
    "NAME": "name",
    "CORES": "cores",
    "MEM": "memory",
    "DISK": "disk",
    "NET_DRIVER": "driver",
    "BRIDGE": "bridge",
    "VLAN": "vlan",
    "CLOUDINIT_NET": "ci_network",
    "CLOUDINIT_UPGRADE": "ci_upgrade"
}

# Dictionary of optional keys and their required first sub-keys
OPTIONAL_KEYS = {
    # Example of possible optional keys and their first sub-keys
    "BALLOON": "balloon",
    "START_AT_BOOT": "boot_start",
    "CLOUDINIT_USER": "ci_username",
    "CLOUDINIT_PW": "ci_password",
    "CLOUDINIT_PUB_KEY": "ci_publickey",
    "CLOUDINIT_DNS_DOMAIN": "ci_domain",
    "CLOUDINIT_DNS_SERVER": "ci_dns_server",
    "CLOUDINIT_IP": "ci_ipaddress",
    "CLOUDINIT_GW": "ci_gwadvalue",
    "CLOUDINIT_MASK": "ci_netmask"
}

def validate_boolean(value, field_name):
    if not isinstance(value, bool):
        print(f"\033[91m[ERROR]           : '{field_name}' must be a boolean (true/false)")
        return False
    return True

def end_output_to_shell():
    print("\033[0m-------------------------------------------")
    print("")

def check_parameters(config_file):
    errors = []
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)

        allowed_keys = set(MANDATORY_KEYS.keys()).union(OPTIONAL_KEYS.keys())

        # Check for invalid keys
        for key in config.keys():
            if key not in allowed_keys:
                errors.append(f"\033[91m[ERROR]           : Invalid key '{key}' found in JSON configuration.")
        # Check for mandatory keys and sub-keys
        for key, sub_key in MANDATORY_KEYS.items():
            if key not in config:
                errors.append(f"\033[91m[ERROR]           : Missing mandatory key '{key}' in JSON configuration.")
            elif sub_key not in config[key]:
                errors.append(f"\033[91m[ERROR]           : Missing mandatory sub-key '{sub_key}' in '{key}' object.")
            elif not validate_boolean(config[key].get("allow_blank", None), f"{key}.allow_blank") or not validate_boolean(config[key].get("allow_spaces", None), f"{key}.allow_spaces"):
                errors.append(f"\033[91m[ERROR]           : Invalid boolean value in {key}")
        # Check for 'comment' key
        for key, obj in config.items():
            if "comment" not in obj:
                print(f"\033[91m[ERROR]           : E'{key}' is missing 'comment' key.")
        if errors:
            for error in errors:
                print(f"\033[91m{error}")
            sys.exit(1)

        print("\033[92m[SUCCESS]         : All parameters are structured correctly")
        end_output_to_shell()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Error reading the configuration file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("[ERROR]           : Usage: validate_json.py <config.json>")
        sys.exit(1)

    config_file = sys.argv[1]
    check_parameters(config_file)
