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

def create_server(ssh, values):
    """Create the server template on the Proxmox host."""
    vm_id = values.get("id")
    print(f"\033[92m[INFO]            : Attempting to create server: {vm_id}")

    try:
        command = f"qm clone {values.get('template_id')} {vm_id} --full 1"
        functions.execute_ssh_command(ssh, command, f"Failed to clone {vm_id} from {values.get('template_id')}.")

        command = f"qm set {vm_id} --cores {values.get('cores')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set # of cores.")

        command = f"qm disk resize {vm_id} scsi0 {values.get('disk')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set disk size.")

        command = f"qm set {vm_id} --name {values.get('name')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set VM name.")

        command = f"qm set {vm_id} --memory {values.get('mem')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set memory size.")

        command = f"qm set {vm_id} --balloon {values.get('balloon')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set memory ballooning.")

        command = f"qm set {vm_id} --net0 {values.get('driver')},bridge={values.get('bridge')},tag={values.get('vlan')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set network driver, brigde or vlan.")

        command = f"qm set {vm_id} --onboot {values.get('start_at_boot')}"
        functions.execute_ssh_command(ssh, command, f"Failed to set start at boot setting.")

        print(f"\033[92m[SUCCESS]         : Server {vm_id} created successfully.")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to create server: {e}")
        functions.end_output_to_shell()
        sys.exit(1)

def create_ssh_public_key(ssh, values):
    vm_id = values.get("id")
    filename = "/tmp/temp_key.pub"
    sftp = ssh.open_sftp()
    try:
        if values.get("ci_publickey"):
            sftp = ssh.open_sftp()
            try:
                with sftp.file(filename, 'w') as file:
                    file.write(values.get("ci_publickey"))
                    print(f"\033[92m[INFO]            : Public key written to '{filename}'.")

                print(f"\033[92m[INFO]            : Attempting to add public key to default user authorized_keys")
                command = f"qm set {vm_id} --sshkeys {filename}"
                functions.execute_ssh_command(ssh, command, f"Failed to set default user public key")
                print(f"\033[92m[SUCCESS]         : Public key added to default user successfully.")
                sftp.remove(filename)
                print(f"\033[92m[INFO]            : Public key '{filename}' removed.")
            except FileNotFoundError:
                print(f"\033[91m[ERROR]           : Remote file '{filename}' does not exist.")
            finally:
                sftp.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to execute command on Proxmox host: {e}\033[0m")

def create_ci_options(ssh, values):
    vm_id = values.get("id")
    print(f"\033[92m[INFO]            : Attempting to set cloud-init settings on: {vm_id}")

    try:
        # Set root password if `ci_password` is provided
        if values.get('ci_network') == "dhcp":
            command = f"qm set {vm_id} --ipconfig0 ip=dhcp"
            functions.execute_ssh_command(ssh, command, f"Failed to set network to DHCP")

        if values.get('ci_network') == "static":
            command = f"qm set {vm_id} --ipconfig0 gw={values.get('ci_gwadvalue')},ip={values.get('ci_ipaddress')}/{values.get('ci_netmask')}"
            functions.execute_ssh_command(ssh, command, f"Failed to set network to static ip")

        if values.get('ci_dns_server'):
            functions.check_valid_ip_address(values, "dns")
            command = f"qm set {vm_id} --nameserver {values.get('ci_dns_server')}"
            functions.execute_ssh_command(ssh, command, f"Failed to set dns server ip")

        if values.get('ci_domain'):
            command = f"qm set {vm_id} --searchdomain {values.get('ci_domain')}"
            functions.execute_ssh_command(ssh, command, f"Failed to set dns domain")

        if values.get("ci_publickey"):
           create_ssh_public_key(ssh, values)

        if values.get("ci_username"):
            command = f"qm set {vm_id} --ciuser {values.get('ci_username')}"
            functions.execute_ssh_command(ssh, command, f"Failed to set user")

        if values.get("ci_password"):
            command = f"qm set {vm_id} --cipassword {values.get('ci_password')}"
            functions.execute_ssh_command(ssh, command, f"Failed to set password")

        if values.get("ci_upgrade"):
            command = f"qm set {vm_id} --ciupgrade {values.get('ci_upgrade')}"
            functions.execute_ssh_command(ssh, command, f"Failed to set update flag")

        print(f"\033[92m[SUCCESS]         : Cloud-init settings on {vm_id} set successfully.")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to set cloud-init settings: {e}")
        functions.end_output_to_shell()
        sys.exit(1)

def create_cloudinit(ssh, values):
    upgrade = values.get("ci_upgrade")
    vm_id = values.get("id")
    remote_filename = f"{vm_id}-cloud-init.yml"
    remote_path = f"/var/lib/vz/snippets/{remote_filename}"

    if upgrade  == 1:
        upgrade = True
    else:
        upgrade = False

    try:
        # Cloud-init content with dynamic values
        cloud_init_content = f"""
#cloud-config
package_upgrade: {str(upgrade).lower()}
package_reboot_if_required: {str(upgrade).lower()}
packages:
  - qemu-guest-agent
runcmd:
"""

        # Open SFTP session to write directly to the file
        sftp = ssh.open_sftp()
        with sftp.file(remote_path, 'w') as remote_file:
            remote_file.write(cloud_init_content)
        sftp.close()

        print(f"\033[92m[SUCCESS]         : cloud-init file copied to Prxmox host successfully.")

        command = f"qm set {vm_id} --cicustom 'user=local:snippets/{remote_filename}'"
        functions.execute_ssh_command(ssh, command, f"Failed to set custom cloud-init file")
        print(f"\033[92m[SUCCESS]         : Custom cloud-init file set for {vm_id }successfully.")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to create cloud-init file: {e}")
        functions.end_output_to_shell()
        sys.exit(1)

def start_vm(ssh, values):
    vm_id = values.get("id")
    try:
        print(f"\033[92m[INFO]            : Attempting to start VM with id: {vm_id}")
        command = f"qm start {vm_id}"
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        if error:
            print(f"\033[91m[ERROR]           : {error}\033[0m")
            functions.end_output_to_shell()
            sys.exit(1)
        else:
            print(f"\033[92m[SUCCESS]         : {output}\033[0m")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to execute command on Proxmox host: {e}\033[0m")

def get_vm_ipv4_address(ssh, values):
    vm_id = values.get("id")
    max_wait_time = 300  # max wait time in seconds
    check_interval = 10  # time interval between retries in seconds
    total_waited = 0

    print(f"\033[92m[INFO]            : Waiting for VM {vm_id} to finalize custom cloud-init setup and reboot...")
    time.sleep(10)  # Wait for 120 seconds for VM to reboot and finalize cloud-init

    while total_waited < max_wait_time:
        try:
            command = f"qm agent {vm_id} network-get-interfaces"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for command to complete
            output = stdout.read().decode('utf-8').strip()
            error_output = stderr.read().decode('utf-8').strip()

            if error_output:
                print(f"\033[92m[INFO]            : VM {vm_id} QEMU agent not responding to request - retrying in {check_interval} sec.")
                total_waited += check_interval
                time.sleep(check_interval)  # Retry after the specified interval
                continue

            # Parse the JSON output from the command
            interfaces = json.loads(output)
            ipv4_address = None

            # Loop through the interfaces to find 'eth0' and its IPv4 address
            for interface in interfaces:
                if interface.get("name") == "eth0":
                    for ip in interface.get("ip-addresses", []):
                        if ip.get("ip-address-type") == "ipv4":
                            ipv4_address = ip.get("ip-address")
                            break

            if ipv4_address:
                print(f"\033[92m[SUCCESS]         : VM {vm_id} has IPv4 address: {ipv4_address} on 'eth0'.")
                return ipv4_address
            else:
                print(f"\033[91m[ERROR]           : No IPv4 address found on 'eth0' interface.")
                total_waited += check_interval
                time.sleep(check_interval)  # Retry after the specified interval

        except Exception as e:
            print(f"\033[91m[ERROR]           : Failed to retrieve VM network interfaces: {e}")
            total_waited += check_interval
            time.sleep(check_interval)  # Retry after the specified interval

    print(f"\033[91m[ERROR]           : Failed to get the VM IPv4 address within {max_wait_time} seconds.")
    return None

def temp_fix_cloudinit(ssh, values):
    vm_id = values.get("id")
    print(f"\033[92m[CI-FIX]          : Attempting to fix cloud-init issue on: {vm_id}")

    try:
        # Set root password if `ci_password` is provided
        if values.get("ci_password"):
            ci_password = values.get('ci_password')
            set_password_cmd = f"qm guest passwd {vm_id} ubuntu --password {ci_password}"
            functions.execute_ssh_command(ssh, set_password_cmd, f"Failed to set password for 'ubuntu' user")
            print(f"\033[92m[CI-FIX]          : Password set for 'ubuntu' user successfully.")

        # Add SSH public key to root's authorized_keys if `ci_publickey` is provided
        if values.get("ci_publickey"):
            ci_publickey = values.get("ci_publickey")
            make_homedir_cmd = f"qm guest exec {vm_id} -- mkdir -p home/ubuntu/.ssh"
            add_to_authorizwed_keys = f"qm guest exec {vm_id} -- sh -c 'echo \"{ci_publickey}\" >> /home/ubuntu/.ssh/authorized_keys'"
            mod_file_permissions_cmd = f"qm guest exec {vm_id} -- chmod 600 /home/ubuntu/.ssh/authorized_keys"
            mod_folder_permissions_cmd = f"qm guest exec {vm_id} -- chmod 700 /home/ubuntu/.ssh"

            functions.execute_ssh_command(ssh, make_homedir_cmd, f"Failed to create homedir for 'ubuntu' user")
            functions.execute_ssh_command(ssh, add_to_authorizwed_keys, f"Failed to add public key to authorized_keys for 'ubuntu' user")
            functions.execute_ssh_command(ssh, mod_file_permissions_cmd, f"Failed to set filepermissions to authorized_keys for 'ubuntu' user")
            functions.execute_ssh_command(ssh, mod_folder_permissions_cmd, f"Failed to set filepermissions to .ssh folder for 'ubuntu' user")

            print(f"\033[92m[CI-FIX]          : Public key added to authorized_keys for 'ubuntu' user successfully.")

        print(f"\033[92m[CI-FIX]          : Cloud-init temp fix on '{vm_id}' set successfully.")
    except Exception as e:
        print(f"\033[91m[CI-FIX]          : Failed fix cloud-init settings: {e}")
        functions.end_output_to_shell()
        sys.exit(1)

def on_guest_temp_fix_cloudinit(ssh, values, ipaddress):
    ci_username = values.get("ci_username")
    ci_password = values.get("ci_password")  # Use unhashed password directly
    ci_publickey = values.get("ci_publickey")

    try:
        # Step 1: Check if user already exists
        check_user_cmd = f"id -u {ci_username}"
        try:
            functions.execute_ssh_command(ssh, check_user_cmd)
            print(f"\033[93m[CI-FIX]          : User '{ci_username}' already exists. No need to apply fix.")
            return
        except:
            print(f"\033[92m[CI-FIX]          : User '{ci_username}' does not exist. Proceeding with user creation.")

        # Step 2: Add ci_username if provided
        if ci_username:
            print(f"\033[92m[CI-FIX]          : Adding user '{ci_username}' with specified password.")

            # Create the user without setting the password initially
            add_user_cmd = f"sudo useradd -m {ci_username}"
            functions.execute_ssh_command(ssh, add_user_cmd, f"Failed to add user '{ci_username}'")
            print(f"\033[92m[CI-FIX]          : User '{ci_username}' added successfully.")

            # Add user to sudo group
            add_sudo_cmd = f"sudo usermod -aG sudo {ci_username}"
            functions.execute_ssh_command(ssh, add_sudo_cmd, f"Failed to add user '{ci_username}' to sudo group")
            print(f"\033[92m[CI-FIX]          : User '{ci_username}' added to sudo group successfully.")

            # Set the user's password
            set_password_cmd = f"echo '{ci_username}:{ci_password}' | sudo chpasswd"
            functions.execute_ssh_command(ssh, set_password_cmd, f"Failed to set password for user '{ci_username}'")
            print(f"\033[92m[CI-FIX]          : Password set successfully for user '{ci_username}'.")

            # Step 3: Add SSH public key to authorized_keys
            if ci_publickey:
                ci_publickey = ci_publickey.strip()

                # Create the .ssh directory and set the correct permissions
                create_ssh_dir_cmd = f"sudo -u {ci_username} mkdir -p /home/{ci_username}/.ssh"
                functions.execute_ssh_command(ssh, create_ssh_dir_cmd, f"Failed to create .ssh directory for '{ci_username}'")

                set_ssh_dir_permissions_cmd = f"sudo chmod 700 /home/{ci_username}/.ssh && sudo chown {ci_username}:{ci_username} /home/{ci_username}/.ssh"
                functions.execute_ssh_command(ssh, set_ssh_dir_permissions_cmd, f"Failed to set permissions for .ssh directory for '{ci_username}'")

                # Add the SSH key to authorized_keys
                add_ssh_key_cmd = f"echo '{ci_publickey}' | sudo -u {ci_username} tee -a /home/{ci_username}/.ssh/authorized_keys > /dev/null"
                functions.execute_ssh_command(ssh, add_ssh_key_cmd, f"Failed to add SSH public key for '{ci_username}'")

                # Set the correct permissions for authorized_keys
                set_auth_keys_permissions_cmd = f"sudo chmod 600 /home/{ci_username}/.ssh/authorized_keys && sudo chown {ci_username}:{ci_username} /home/{ci_username}/.ssh/authorized_keys"
                functions.execute_ssh_command(ssh, set_auth_keys_permissions_cmd, f"Failed to set permissions for authorized_keys for '{ci_username}'")

                print(f"\033[92m[CI-FIX]          : SSH public key added successfully for user '{ci_username}'.")

        # Step 4: Perform a login test with the newly created user
        print(f"\033[92m[INFO]            : Performing login test for user '{ci_username}'.")
        login_attempts = 3
        for attempt in range(1, login_attempts + 1):
            try:
                test_ssh = functions.ssh_connect(ipaddress, ci_username, ci_password)  # Use unhashed password for login test
                print(f"\033[92m[CI-FIX]          : Login test successful for user '{ci_username}'.")
                break
            except Exception as e:
                if attempt == login_attempts:
                    print(f"\033[91m[CI-FIX]          : Login test failed for user '{ci_username}' after {login_attempts} attempts: {e}\033[0m")
                    functions.end_output_to_shell()
                    sys.exit(1)
                else:
                    print(f"\033[93m[CI-FIX]          : Login attempt {attempt} failed for user '{ci_username}'. Retrying...")
                    time.sleep(5)

        # Test sudo access after login
        print(f"\033[92m[CI-FIX]          : Testing sudo access for user '{ci_username}'.")
        try:
            sudo_test_cmd = f"echo '{ci_password}' | sudo -S whoami"  # Use unhashed password for sudo test
            stdin, stdout, stderr = test_ssh.exec_command(sudo_test_cmd)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0 and 'root' in stdout.read().decode().strip():
                print(f"\033[92m[CI-FIX]          : Sudo access verified for user '{ci_username}'.")
            else:
                print(f"\033[91m[CI-FIX]          : Sudo access test failed for user '{ci_username}'.\033[0m")
                functions.end_output_to_shell()
                sys.exit(1)
        except Exception as e:
            print(f"\033[91m[CI-FIX]          : Sudo access test failed for user '{ci_username}': {e}\033[0m")
            functions.end_output_to_shell()
            sys.exit(1)
        finally:
            test_ssh.close()

    except Exception as e:
        print(f"\033[91m[CI-FIX]          : Failed to execute command on {ipaddress}: {e}\033[0m")
        functions.end_output_to_shell()
        sys.exit(1)

def on_guest_temp_fix_cloudinit_part_2(ssh, values, ipaddress):
    ci_password = values.get("ci_password")  # Use unhashed password directly
    ci_username = values.get("ci_username")


    try:
        # Step 0: Check for any running processes by the 'ubuntu' user
        check_processes_cmd = f"echo '{ci_password}' | sudo -S pgrep -u ubuntu"
        processes = functions.execute_ssh_command(ssh, check_processes_cmd, f"Failed to grep processes for 'ubuntu' user")

        if processes:
            print(f"\033[93m[CI-FIX]          : Processes found for user 'ubuntu': {processes.strip()}\033[0m")

            # Kill all processes belonging to 'ubuntu' user
            kill_processes_cmd = f"echo '{ci_password}' | sudo -S pkill -u ubuntu"
            functions.execute_ssh_command(ssh, kill_processes_cmd, f"Failed to kill processes for 'ubuntu' user")
            print(f"\033[92m[CI-FIX]          : All processes for 'ubuntu' user killed successfully.")
        else:
            print(f"\033[92m[CI-FIX]          : No running processes found for user 'ubuntu'.\033[0m")

        # Step 1: Disable the default ubuntu user
        disable_ubuntu_cmd = f"echo '{ci_password}' | sudo -S deluser --remove-home ubuntu"
        functions.execute_ssh_command(ssh, disable_ubuntu_cmd, f"Failed to delete 'ubuntu' user")
        print(f"\033[92m[CI-FIX]          : User 'ubuntu' deleted successfully.")

    except Exception as e:
        print(f"\033[91m[CI-FIX]          : Failed to execute command on {ipaddress}: {e}\033[0m")
        functions.end_output_to_shell()
        sys.exit(1)

def on_guest_configuration(ssh, values, ipaddress):
    ci_password = values.get("ci_password")  # Use unhashed password directly
    ci_username = values.get("ci_username")
    try:
        change_shell_cmd = f"echo '{ci_password}' | chsh -s /bin/bash"
        functions.execute_ssh_command(ssh, change_shell_cmd, f"Failed to change shell to BASH")
        print(f"\033[92m[SUCCESS]         : Shell changed to BASH successfully.")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to execute command on {ipaddress}: {e}\033[0m")
        functions.end_output_to_shell()
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

# Define mandatory and optional keys to pass to check_parameters function
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

OPTIONAL_KEYS = {
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

# Use json_test to validate JSON structure
json_test.check_parameters(config, MANDATORY_KEYS, OPTIONAL_KEYS)

print("-------------------------------------------")
print("--          Validate JSON values         --")
print("-------------------------------------------")
# Define keys that are expected to be integers
INTEGER_KEYS = ["TEMPLATE", "ID", "CORES", "MEM", "VLAN", "CLOUDINIT_UPGRADE", "CLOUDINIT_MASK"]

# Validate JSON values to ensure proper types
json_test.check_values(config, integer_keys=INTEGER_KEYS)

print("-------------------------------------------")
print("-- Validate JSON conditions and build VM --")
print("-------------------------------------------")
check_conditional_values(values)

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
ssh = functions.ssh_connect(ipaddress, ci_username)
on_guest_temp_fix_cloudinit_part_2(ssh, values, ipaddress)
on_guest_configuration(ssh, values, ipaddress)
#functions.configure_sshd_config(ssh, values)
ssh.close()

functions.end_output_to_shell()