#!/usr/bin/env python3

import json
import sys
import re
import paramiko
import time
import random
import string


print("-------------------------------------------")
print("-- Validate JSON conditions and build VM --")
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

def ssh_connect(host, username, password=None):
    """Establish SSH connection to the remote host securely using key-based auth."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            ssh.connect(hostname=host, username=username, password=password)
        else:
            ssh.connect(hostname=host, username=username)
        print(f"\033[92m[SUCCESS]         : Successfully connected to {host} as {username}.")
        return ssh
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to connect to {host} as {username}: {e}")
        sys.exit(1)

def check_vlan(values):
    value_string = values.get("vlan")
    try:
        vlan= int(value_string)
        if not vlan in range(2, 4095):
            print(f"\033[91m[ERROR]           : Invalid VLAN '{vlan}'. Vlan should be a number between 2 and 4094.")
            end_output_to_shell()
            sys.exit(1)

    except ValueError:
        print(f"\033[91m[ERROR]           : Invalid VLAN '{value_string}'. Vlan id must be a number.")
        end_output_to_shell()
        sys.exit(1)

    print(f"\033[92m[INFO]            : VLAN id '{value_string}' is a valid VLAN.")

def is_valid_hostname(values):
    vm_name = values.get("name")
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    if len(vm_name) > 253:
        return False

    labels = vm_name.split('.')

    for label in labels:
        if not hostname_regex.match(label):
            return False

    return True

def check_valid_ip_address(value_string):
    parts = value_string.split('.')
    vlan = values.get("vlan")

    if len(parts) != 4:
        print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. IP address should have exactly four parts.")
        end_output_to_shell()
        sys.exit(1)

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be between 0 and 255.")
                end_output_to_shell()
                sys.exit(1)
        except ValueError:
            print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be an integer.")
            end_output_to_shell()
            sys.exit(1)

    print(f"\033[92m[INFO]            : IP address '{value_string}' is a valid ip-address.")

    if not int(vlan) == int(parts[2]):
        print(f"\033[91m[ERROR]           : IP address 3rd octect '{parts[2]}' does not match VLAN ID '{vlan}'.")
        end_output_to_shell()
        sys.exit(1)

def check_valid_dns_ip_address(value_string):
    parts = value_string.split('.')
    vlan = values.get("vlan")

    if len(parts) != 4:
        print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. IP address should have exactly four parts.")
        end_output_to_shell()
        sys.exit(1)

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be between 0 and 255.")
                end_output_to_shell()
                sys.exit(1)
        except ValueError:
            print(f"\033[91m[ERROR]           : Invalid IP address '{value_string}'. Each part should be an integer.")
            end_output_to_shell()
            sys.exit(1)

    print(f"\033[92m[INFO]            : IP address '{value_string}' is a valid ip-address.")

    if not int(vlan) == int(parts[2]):
        print(f"\033[91m[ERROR]           : IP address 3rd octect '{parts[2]}' does not match VLAN ID '{vlan}'. Continuing...")

def check_netmask(values):
    value_string = values.get("ci_netmask")
    try:
        netmask = int(value_string)
        if not netmask in range(23, 30):
            print(f"\033[91m[ERROR]           : Invalid netmask '{value_string}'. Netmask is not a number between /24 and /29.")
            return
    except ValueError:
        print(f"\033[91m[ERROR]           : Invalid netmask '{value_string}'. Netmask is not a number value.")
        return

    print(f"\033[92m[INFO]            : Netmask '/{netmask}' is a valid netmask.")

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
            check_vlan(values)
            check_valid_ip_address(values.get("ci_ipaddress"))
            check_valid_ip_address(values.get("ci_gwadvalue"))
            check_netmask(values)
    else:
        print(f"\033[91m[ERROR]           : Invalid network type '{ci_network}', expected 'dhcp' or 'static'")

    if not is_valid_hostname(values):
        print(f"\033[91m[ERROR]           : '{values['name']}' is not a valid hostname. Only A-Z, a-z, 0-9 and '-' allowed.\033[0m")
        end_output_to_shell()
        sys.exit(1)

def create_server(ssh, values):
    """Create the server template on the Proxmox host."""
    try:
        vm_id = values.get("id")
        commands = [
            f"qm clone {values.get('template_id')} {vm_id} --full 1",
            f"qm set {vm_id} --cores {values.get('cores')}",
            f"qm disk resize {vm_id} scsi0 {values.get('disk')}",
            f"qm set {vm_id} --name {values.get('name')}",
            f"qm set {vm_id} --memory {values.get('mem')}",
            f"qm set {vm_id} --balloon {values.get('balloon')}",
            f"qm set {vm_id} --net0 {values.get('driver')},bridge={values.get('bridge')},tag={values.get('vlan')}",
            f"qm set {vm_id} --onboot {values.get('start_at_boot')}",
        ]

        # Execute each command via SSH
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for command to complete
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"\033[91m[ERROR]           : Command '{command}' failed with error: {error_output}")
                sys.exit(1)

        print(f"\033[92m[SUCCESS]         : Virtual server '{vm_id}' created successfully on the Proxmox host.")
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to create virtual server: {e}")
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

                print(f"\033[92m[INFO]            : Attempting to set default user public key on VM with id: '{vm_id}'")
                command = f"qm set {vm_id} --sshkeys {filename}"
                stdin, stdout, stderr = ssh.exec_command(command)
                output = stdout.read().decode('utf-8')
                error = stderr.read().decode('utf-8')

                if error:
                    print(f"\033[91m[ERROR]           : {error}\033[0m")
                    end_output_to_shell()
                    sys.exit(1)
                else:
                    print(f"\033[92m[SUCCESS]         : {output}\033[0m")

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
    commands = []
    try:

        if values.get('ci_network') == "dhcp":
            commands.append(f"qm set {vm_id} --ipconfig0 ip=dhcp")

        if values.get('ci_network') == "static":
             commands.append(f"qm set {vm_id} --ipconfig0 gw={values.get('ci_gwadvalue')},ip={values.get('ci_ipaddress')}/{values.get('ci_netmask')}")

        if values.get('ci_dns_server'):
            check_valid_dns_ip_address(values.get('ci_dns_server'))
            commands.append(f"qm set {vm_id} --nameserver {values.get('ci_dns_server')}")

        if values.get('ci_domain'):
            commands.append(f"qm set {vm_id} --searchdomain {values.get('ci_domain')}")

        if values.get("ci_publickey"):
           create_ssh_public_key(ssh, values)

        if values.get("ci_username"):
           commands.append(f"qm set {vm_id} --ciuser {values.get('ci_username')}")

        if values.get("ci_password"):
           commands.append(f"qm set {vm_id} --cipassword {values.get('ci_password')}")

        if values.get("ci_upgrade"):
            commands.append(f"qm set {vm_id} --ciupgrade {values.get('ci_upgrade')}")

        # Execute each command via SSH
        for command in commands:
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for command to complete
            error_output = stderr.read().decode().strip()
            if error_output:
                print(f"\033[91m[ERROR]           : Command '{command}' failed with error: {error_output}")
                sys.exit(1)

        print(f"\033[92m[SUCCESS]         : Additional settings on '{vm_id}' set successfully.")
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to set additional settings: {e}")
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

        print(f"\033[92m[SUCCESS]         : cloud-init file created successfully at {remote_path} on host.")

        command = f"qm set {vm_id} --cicustom 'user=local:snippets/{remote_filename}'"
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.channel.recv_exit_status()  # Wait for command to complete
        error_output = stderr.read().decode().strip()
        if error_output:
            print(f"\033[91m[ERROR]           : Command '{command}' failed with error: {error_output}")
            sys.exit(1)
        else:
            print(f"\033[92m[SUCCESS]         : Command '{command}' executed successfully.")

        print(f"\033[92m[SUCCESS]         : Cloud-init for '{vm_id}' successfully added to snippets on the Proxmox host.")

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to create cloud-init file: {e}")
        sys.exit(1)

def start_vm(ssh, values):
    vm_id = values.get("id")
    try:
        print(f"\033[92m[INFO]            : Attempting to start VM with id: '{vm_id}'")
        command = f"qm start {vm_id}"
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        if error:
            print(f"\033[91m[ERROR]           : {error}\033[0m")
            end_output_to_shell()
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

    print(f"\033[92m[INFO]            : Waiting for VM '{vm_id}' to finalize custom cloud-init setup and reboot...")
    time.sleep(10)  # Wait for 120 seconds for VM to reboot and finalize cloud-init

    while total_waited < max_wait_time:
        try:
            command = f"qm agent {vm_id} network-get-interfaces"
            stdin, stdout, stderr = ssh.exec_command(command)
            stdout.channel.recv_exit_status()  # Wait for command to complete
            output = stdout.read().decode('utf-8').strip()
            error_output = stderr.read().decode('utf-8').strip()

            if error_output:
                print(f"\033[92m[INFO]            : VM '{vm_id}' QEMU agent not responding to request - retrying in {check_interval} sec.")
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
                print(f"\033[92m[SUCCESS]         : VM '{vm_id}' has IPv4 address '{ipv4_address}' on 'eth0'.")
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
    commands = []

    try:
        # Step 2: Set root password if `ci_password` is provided
        if values.get("ci_password"):
            ci_password = values.get('ci_password')
            commands.append(f"qm guest passwd {vm_id} root --password {ci_password}")

        # Step 3: Add SSH public key to root's authorized_keys if `ci_publickey` is provided
        if values.get("ci_publickey"):
            ci_publickey = values.get("ci_publickey")

            # Command 1: Create the .ssh directory for root
            commands.append(f"qm guest exec {vm_id} -- mkdir -p /root/.ssh")

            # Command 2: Append the public key to authorized_keys
            commands.append(f"qm guest exec {vm_id} -- sh -c 'echo \"{ci_publickey}\" >> /root/.ssh/authorized_keys'")



            # Command 3: Set permissions on the authorized_keys file and .ssh directory
            commands.append(f"qm guest exec {vm_id} -- chmod 600 /root/.ssh/authorized_keys")
            commands.append(f"qm guest exec {vm_id} -- chmod 700 /root/.ssh")

        print(f"\033[92m[INFO]            : Attempting to fix cloud-init issue on: '{vm_id}'")

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

        print(f"\033[92m[SUCCESS]         : Additional settings on '{vm_id}' set successfully.")
    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to set additional settings: {e}")
        sys.exit(1)

def wait_for_reboot(host, username, password=None, timeout=300, interval=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                ssh.connect(hostname=host, username=username, password=password)
            else:
                ssh.connect(hostname=host, username=username)
            print(f"\033[92m[SUCCESS]         : Successfully reconnected to {host} after reboot.")
            return ssh
        except Exception:
            print(f"\033[93m[INFO]            : Waiting for VM '{host}' to reboot...")
            time.sleep(interval)
    print(f"\033[91m[ERROR]           : Timeout while waiting for {host} to reboot.")
    sys.exit(1)

def execute_ssh_command(ssh, command, error_message):
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    error_output = stderr.read().decode().strip()
    if exit_status != 0:
        print(f"\033[91m[ERROR]           : {error_message}: {error_output}\033[0m")
        sys.exit(1)
    return stdout.read().decode().strip()

def generate_random_password(length=24):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for i in range(length))

def on_guest_temp_fix_cloudinit(ssh, values, ipaddress):
    ci_username = values.get("ci_username")
    ci_password = values.get("ci_password")  # Use unhashed password directly
    ci_publickey = values.get("ci_publickey")

    try:
        # Step 1: Check if user already exists
        check_user_cmd = f"id -u {ci_username}"
        try:
            execute_ssh_command(ssh, check_user_cmd, f"User '{ci_username}' does not exist, proceeding with creation.")
            print(f"\033[93m[INFO]            : User '{ci_username}' already exists. No need to apply fix.")
            return
        except:
            print(f"\033[92m[INFO]            : User '{ci_username}' does not exist. Proceeding with user creation.")

        # Step 2: Add ci_username if provided
        if ci_username:
            print(f"\033[92m[INFO]            : Adding user '{ci_username}' with specified password.")

            # Command to create user without setting the password initially
            add_user_cmd = f"useradd -m {ci_username}"
            execute_ssh_command(ssh, add_user_cmd, f"Failed to add user '{ci_username}'")
            print(f"\033[92m[SUCCESS]         : User '{ci_username}' added successfully.")

            # Add user to sudo group
            add_sudo_cmd = f"usermod -aG sudo {ci_username}"
            execute_ssh_command(ssh, add_sudo_cmd, f"Failed to add user '{ci_username}' to sudo group")
            print(f"\033[92m[SUCCESS]         : User '{ci_username}' added to sudo group successfully.")

            # Re-check if the user was added successfully
            execute_ssh_command(ssh, check_user_cmd, f"Failed to verify user '{ci_username}' after creation.")
            print(f"\033[92m[SUCCESS]         : User '{ci_username}' verified successfully.")

            # Command to set password for the user using unhashed password
            set_password_cmd = f"echo '{ci_username}:{ci_password}' | chpasswd"
            execute_ssh_command(ssh, set_password_cmd, f"Failed to set password for user '{ci_username}'")
            print(f"\033[92m[SUCCESS]         : Password set successfully for user '{ci_username}'.")

            # Step 3: Add SSH public key to ci_username's authorized_keys
            if ci_publickey:
                print(f"\033[92m[INFO]            : Adding SSH public key to '{ci_username}'.")

                # Command to create the .ssh directory in the user's home
                create_ssh_dir_cmd = f"mkdir -p /home/{ci_username}/.ssh && chmod 700 /home/{ci_username}/.ssh"
                execute_ssh_command(ssh, create_ssh_dir_cmd, f"Failed to create .ssh directory for '{ci_username}'")

                # Command to set the correct owner and group for the .ssh directory
                set_ssh_owner_cmd = f"chown -R {ci_username}:{ci_username} /home/{ci_username}/.ssh && chmod 700 /home/{ci_username}/.ssh"
                execute_ssh_command(ssh, set_ssh_owner_cmd, f"Failed to set ownership for .ssh directory for '{ci_username}'")

                # Command to add the SSH key to authorized_keys
                add_ssh_key_cmd = f"echo '{ci_publickey}' >> /home/{ci_username}/.ssh/authorized_keys && chmod 600 /home/{ci_username}/.ssh/authorized_keys"
                execute_ssh_command(ssh, add_ssh_key_cmd, f"Failed to add SSH public key for '{ci_username}'")
                print(f"\033[92m[SUCCESS]         : SSH public key added successfully for user '{ci_username}'.")

                # Command to set the correct owner and permissions for authorized_keys
                set_auth_keys_owner_cmd = f"chown {ci_username}:{ci_username} /home/{ci_username}/.ssh/authorized_keys && chmod 600 /home/{ci_username}/.ssh/authorized_keys"
                execute_ssh_command(ssh, set_auth_keys_owner_cmd, f"Failed to set ownership and permissions for authorized_keys for '{ci_username}'")

                # Re-check if the SSH key was added successfully
                verify_ssh_key_cmd = f"grep '{ci_publickey}' /home/{ci_username}/.ssh/authorized_keys"
                execute_ssh_command(ssh, verify_ssh_key_cmd, f"Failed to verify SSH public key for '{ci_username}' in authorized_keys.")
                print(f"\033[92m[SUCCESS]         : SSH public key verified successfully for user '{ci_username}'.")

        # Step 4: Perform a login test with the newly created user
        print(f"\033[92m[INFO]            : Performing login test for user '{ci_username}'.")
        test_ssh = paramiko.SSHClient()
        test_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        login_attempts = 3
        for attempt in range(1, login_attempts + 1):
            try:
                test_ssh.connect(hostname=ipaddress, username=ci_username, password=ci_password)  # Use unhashed password for login test
                print(f"\033[92m[SUCCESS]         : Login test successful for user '{ci_username}'.")
                break
            except Exception as e:
                if attempt == login_attempts:
                    print(f"\033[91m[ERROR]           : Login test failed for user '{ci_username}' after {login_attempts} attempts: {e}\033[0m")
                    sys.exit(1)
                else:
                    print(f"\033[93m[INFO]            : Login attempt {attempt} failed for user '{ci_username}'. Retrying...")
                    time.sleep(5)

        # Test sudo access after login
        print(f"\033[92m[INFO]            : Testing sudo access for user '{ci_username}'.")
        try:
            sudo_test_cmd = f"echo '{ci_password}' | sudo -S whoami"  # Use unhashed password for sudo test
            stdin, stdout, stderr = test_ssh.exec_command(sudo_test_cmd)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0 and 'root' in stdout.read().decode().strip():
                print(f"\033[92m[SUCCESS]         : Sudo access verified for user '{ci_username}'.")
            else:
                print(f"\033[91m[ERROR]           : Sudo access test failed for user '{ci_username}'.\033[0m")
                sys.exit(1)
        except Exception as e:
            print(f"\033[91m[ERROR]           : Sudo access test failed for user '{ci_username}': {e}\033[0m")
            sys.exit(1)
        finally:
            test_ssh.close()

    except Exception as e:
        print(f"\033[91m[ERROR]           : Failed to execute command on {ipaddress}: {e}\033[0m")
        sys.exit(1)

config_file = sys.argv[1]
config = load_config(config_file)
values = get_json_values(config)
check_conditional_values(values)

# Establish SSH connection to Proxmox server
ssh = ssh_connect(values.get("host"), values.get("user"))

# Create and configure the VM
create_server(ssh, values)
create_ci_options(ssh, values)
create_cloudinit(ssh, values)
start_vm(ssh, values)

# Wait and get the VM's IPv4 address
ipaddress = get_vm_ipv4_address(ssh, values)
temp_fix_cloudinit(ssh, values)
ssh.close()
ssh = ssh_connect(ipaddress, "root")
on_guest_temp_fix_cloudinit(ssh, values, ipaddress)

end_output_to_shell()