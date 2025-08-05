#!/usr/bin/env python3
import os
import sys
import argparse
import yaml
import shlex
import time

from lib.output_handler import OutputHandler
from lib.check_files_handler import CheckFiles
from lib.yaml_config_loader import LoaderNoDuplicates
from lib.proxmox_host_handler import ProxmoxHost
from lib.ssh_handler import SSHConnection
from cerberus import Validator
from urllib.parse import unquote


DEFAULT_YAML_VALIDATION_FILE = "config/guest_config_validation.yaml"
DEFAULT_LOGFILE = "logs/create_guest.log"
output = OutputHandler(DEFAULT_LOGFILE)


def parse_args():
    parser = argparse.ArgumentParser(description="Create Proxmox guest")
    parser.add_argument(
        "--config",
        dest="config_file",
        required=True,
        help="Path to your configuration YAML file for the Proxmox guest"
    )
    parser.add_argument(
        "--validation",
        dest="validation_file",
        default=DEFAULT_YAML_VALIDATION_FILE,
        help=(
            "Optional: Specify a differant set of validation rules "
            "for the config file, if the default file is not to be used"
        )
    )
    return parser.parse_args()


def check_files(args):
    filename = os.path.basename(args)
    checker = CheckFiles(args)
    if checker.check():
        output.output(f"{filename} access checks passed", type="s")
    else:
        for i, error in enumerate(checker.errors):
            is_last = (i == len(checker.errors) - 1)
            if not is_last:
                output.output(
                    f"{filename} access checks failed: {error}",
                    type="e"
                    )
            else:
                output.output(
                    f"{filename} access checks failed: {error}",
                    type="e",
                    exit_on_error=True
                    )


def load_yaml_file(yaml_file: str) -> dict:
    try:
        with open(yaml_file, "r") as fh:
            return yaml.load(
                fh.read(), Loader=LoaderNoDuplicates
            )
    except Exception as e:
        output.output(
            f'File yaml load error in "{yaml_file}": {e}',
            "e",
            exit_on_error=True
            )
        return {}


def validate_config(config, validation_rules):
    validator = Validator(validation_rules)
    if not validator.validate(config):
        for field, errors in validator.errors.items():
            for error in errors:
                output.output(f"{field}: {error}", type="e")
        output.output(
            "Configuration validation failed",
            type="e",
            exit_on_error=True
        )
    else:
        output.output("Configuration validation passed", type="s")
        return validator.document


def run_or_die(host, cmd, ok_msg, fail_prefix="Command failed"):
    r = host.run(cmd)
    if r["exit_code"] != 0:
        output.output(
            f"{fail_prefix}: {r.get('stderr', '').strip() or cmd}",
            "e",
            exit_on_error=True
            )
    output.output(ok_msg, "s")


def countdown(handler, seconds):
    for i in range(seconds, 0, -1):
        handler.output(f"Continueing in {i} seconds...", type='p')
        time.sleep(1)
    print()  # Move to the next line after countdown


def main():
    args = parse_args()
    this_script = os.path.abspath(__file__)

    output.output()
    output.output("Create template on Proxmox Host", type="h")
    output.output()
    output.output(f"Initial script      : {sys.argv[0]}", type="i")
    output.output(f"Active script       : {this_script}", type="i")
    output.output(f"Config file         : {args.config_file}", type="i")
    output.output(f"Validation file     : {args.validation_file}", type="i")
    output.output(f"Default logfile     : {DEFAULT_LOGFILE}", type="i")
    output.output()
    output.output("Checking files", type="h")
    output.output()

    # -------------------------------------------------------------------------
    # Check config yaml files and get specific and defualt configuration
    # -------------------------------------------------------------------------
    check_files(args.config_file)
    check_files(args.validation_file)
    config_values = load_yaml_file(args.config_file)
    validation_rules = load_yaml_file(args.validation_file)
    vc = validate_config(config_values, validation_rules)
    if not vc:
        output.output(
            "Error retrieving config from yaml-files",
            "e",
            exit_on_error=True
            )
        return

    max_key_len = max(len(key) for key in vc)
    for key in vc:
        label = "set by user" if key in config_values else "using default"
        output.output(f"{key.ljust(max_key_len + 1)}: {label}", type="i")

    # -------------------------------------------------------------------------
    # Set the ssh parameter for the SSH connection in class
    # -------------------------------------------------------------------------
    host = ProxmoxHost(
        host=vc["host_ip"],
        username=vc["host_username"],
        key_filename=vc["host_keyfile"],
    )

    output.output()
    output.output("Checking SSH connectivity", type="h")
    output.output()

    connect_flag, connect_message = host.connect()
    output.output(
        connect_message,
        type="s" if connect_flag else "e",
        exit_on_error=not connect_flag
        )

    # -------------------------------------------------------------------------
    # setting up the virtual guest machine
    # -------------------------------------------------------------------------

    output.output()
    output.output("Cloning new or updating existing machine", "h")
    output.output()

    vmid = vc["id"]
    """ Check if guest id is in use and if clone id exists """
    ok, msg = host.clone_vmid_if_missing(
        vc["clone_id"],
        vc["id"]
        )
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    """ Cloudinit drive for virtual machine """
    ci_storage = vc.get("local_storage")
    if ci_storage:
        steps = host.ensure_cloudinit_drive(
            vmid=vc["id"],
            storage=vc["local_storage"],
            bus="ide",
            slot=2
        )
        for ok, msg, lvl in steps:
            output.output(msg, lvl)
            if not ok:
                output.output(
                    "Aborting due to Cloud-Init drive error.",
                    "e",
                    exit_on_error=True
                    )
    else:
        output.output(
            "No 'local_storage' provided; skipping Cloud-Init drive attach.",
            "i"
            )

    # -------------------------------------------------------------------------
    # Create plan for virtual machine
    # -------------------------------------------------------------------------

    ci_changed = False
    """  --- Read current state --- """
    ok, st = host.get_qm_status(vc["id"])
    output.output(
        "Fetched qm status.",
        "s" if ok else "e",
        exit_on_error=not ok
        )

    ok, cfg = host.get_qm_config(vc["id"])
    output.output(
        "Fetched qm config.",
        "s" if ok else "e",
        exit_on_error=not ok
        )

    """ --- Plan changes (only apply diffs) --- """
    vmid = vc["id"]
    plan: list[tuple[str, str]] = []

    """ name """
    desired_name = shlex.quote(vc["name"])
    if st.get("name") != vc["name"]:
        plan.append((
            f"qm set {vmid} --name {desired_name}",
            f"Set name to {vc['name']}"
            ))

    """ cores """
    if cfg.get("cores") != str(vc["cores"]):
        plan.append((
            f"qm set {vmid} --cores {vc['cores']}",
            f"Set cores to {vc['cores']}"
            ))

    """ memory """
    if cfg.get("memory") != str(vc["memory"]):
        plan.append((
            f"qm set {vmid} --memory {vc['memory']}",
            f"Set memory to {vc['memory']} MB"))

    """ balloon """
    desired_balloon = str(vc["balloon"])
    if cfg.get("balloon") != desired_balloon:
        plan.append((
            f"qm set {vmid} --balloon {desired_balloon}",
            f"Set balloon to {desired_balloon}"
            ))

    """ start on boot """
    desired_onboot = "1" if vc["boot_start"] else "0"
    if cfg.get("onboot") != desired_onboot:
        plan.append((
            f"qm set {vmid} --onboot {desired_onboot}",
            f"Set onboot={desired_onboot}"
            ))

    """ NIC (model + bridge + vlan tag) """
    want_model = vc["driver"]
    want_bridge = vc["bridge"]
    want_tag = vc["vlan"]
    current_net = host.parse_net_kv(cfg.get("net0", ""))
    model_net = current_net.get("model", "")
    actual_model = model_net.split('=')[0]
    actual_bridge = current_net.get("bridge", "")
    actual_tag = current_net.get("tag", "")
    actual_model = model_net.split('=')[0]

    need_net = (
        actual_model != want_model or
        actual_bridge != want_bridge or
        str(actual_tag) != str(want_tag)
    )
    if need_net:
        net_str = f"{want_model},bridge={want_bridge},tag={want_tag}"
        plan.append((
            f"qm set {vmid} --net0 {shlex.quote(net_str)}",
            f"Set net0 to {net_str}"
            ))

    """ cloud-init user/pass/domain/dns/upgrade """
    if (
        "ci_username" in vc
        and cfg.get("ciuser") != vc["ci_username"]
    ):
        plan.append((
            f"qm set {vmid} --ciuser "
            f"{shlex.quote(vc['ci_username'])}",
            f"Set ciuser={vc['ci_username']}"
        ))

    if (
        "ci_password" in vc
        and cfg.get("cipassword") != '**********'
    ):
        plan.append((
            f"qm set {vmid} --cipassword "
            f"{shlex.quote(vc['ci_password'])}",
            "Set ci password"
        ))

    if (
        "ci_domain" in vc
        and cfg.get("searchdomain") != vc["ci_domain"]
    ):
        plan.append((
            f"qm set {vmid} --searchdomain "
            f"{shlex.quote(vc['ci_domain'])}",
            f"Set searchdomain={vc['ci_domain']}"
            ))

    if (
        "ci_dns_server" in vc
        and cfg.get("nameserver") != vc["ci_dns_server"]
    ):
        plan.append((
            f"qm set {vmid} --nameserver "
            f"{shlex.quote(vc['ci_dns_server'])}",
            f"Set nameserver={vc['ci_dns_server']}"
            ))

    """ current value from `qm config` (usually '1' or '0') """
    current = str(cfg.get("ciupgrade", "")).strip()
    """ desired value from YAML (boolean) converted to '1'/'0' """
    desired = host.bool(vc.get("ci_upgrade"))

    if "ci_upgrade" in vc and current != desired:
        plan.append((
            f"qm set {vmid} --ciupgrade {desired}",
            f"Set ciupgrade={desired}"
        ))

    # -------------------------------------------------------------------------
    # Apply plan with changes to virtual machine
    # -------------------------------------------------------------------------
    if len(plan) > 0:
        output.output()
        output.output("Applying configuration deltas", "h")
        output.output()
        ci_changed = True
        for cmd, msg_ok in plan:
            run_or_die(host, cmd, msg_ok, "Failed to apply qm setting")

    """ SSH public keys (list) """
    """ Decode sshkeys and split into list of lines """
    current_raw = cfg.get("sshkeys", "")
    current_keys = unquote(current_raw).strip().splitlines()
    desired_raw = vc.get("ci_publickey", [])
    desired_keys = []
    for key in desired_raw:
        stripped = key.strip()
        if stripped:
            desired_keys.append(stripped)

    missing_keys = []
    for desired_key in desired_keys:
        if desired_key not in current_keys:
            missing_keys.append(desired_key)

    if missing_keys:
        ok, msg = host.ensure_sshkeys(vmid, desired_keys)
        output.output(msg, "s" if ok else "e", exit_on_error=not ok)
        ci_changed = True

    """ cloud-init networking """
    # Desired config
    want_net = vc["ci_network"].lower()
    cfg_ipconfig = cfg.get("ipconfig0", "").lower()

    # -----------------------
    # Case 1: Set to DHCP if needed
    # -----------------------
    if want_net == "dhcp":
        if "dhcp" not in cfg_ipconfig:
            ok, msg = host.set_ci_network(vmid, "dhcp")
            output.output(msg, "s" if ok else "e", exit_on_error=not ok)
            if ok:
                ci_changed = True

    # -----------------------
    # Case 2: Set to STATIC if needed
    # -----------------------
    elif want_net == "static":
        # Parse actual guest config (from qm config)
        ip_part = ""
        sub_part = ""
        gw_part = ""

        for item in cfg.get("ipconfig0", "").split(","):
            item = item.strip()
            if item.startswith("ip="):
                val = item[3:]
                if "/" in val:
                    ip_part, sub_part = val.split("/", 1)
            elif item.startswith("gw="):
                gw_part = item[3:]

        # Desired values
        ip = vc.get("ci_ipaddress", "")
        gw = vc.get("ci_gateway", "")
        cidr = vc.get("ci_netmask", "").lstrip("/")

        # If anything differs, update guest
        if ip != ip_part or gw != gw_part or cidr != sub_part:
            ok, msg = host.set_ci_network(
                vmid,
                "static",
                ip=ip,
                gw=gw,
                cidr=cidr
            )
            output.output(msg, "s" if ok else "e", exit_on_error=not ok)
            if ok:
                ci_changed = True

    """ regenerate cloud-init """
    if ci_changed:
        ok, msg = host.cloudinit_update(vmid)
        output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    """ start VM """
    output.output()
    output.output("Starting VM", "h")
    output.output()
    ok, msg = host.start_vm(vmid, ci_changed)
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    # -------------------------------------------------------------------------
    # On-guest configuration and finalization
    # -------------------------------------------------------------------------
    found_ip = []

    if ci_changed:
        wait_in_sec = 90
        output.output(
            f"Waiting {wait_in_sec}s for guest network to come up",
            "i"
            )
        countdown(output, wait_in_sec)

    output.output()
    output.output("Finalising VM config", type="h")
    output.output()

    # DHCP case: scan subnet for IPs
    if vc['ci_network'].lower() == "dhcp":
        subnet = f"{vc['ip_prefix']}.{vc['vlan']}.0"
        port = 22
        ok, results = host.subnet_scan(subnet, port)

        if not ok:
            output.output(
                results[0][0],  # First item is the error message
                "e",
                exit_on_error=True
            )

        fqdn = f"{vc['name']}.{vc['ci_domain']}"

        for ip, hostname in results:
            if hostname == fqdn:
                found_ip.append(ip)

        # If no exact match, fallback to all found IPs
        if not found_ip:
            found_ip = [ip for ip, _ in results]

    # STATIC fallback: use known config
    if not found_ip:
        static_ip = vc.get("ci_ipaddress")
        if static_ip:
            found_ip = [static_ip]

    if not found_ip:
        output.output(
            "Error retrieving IP address of VM",
            "e",
            exit_on_error=True
        )

    # -------------------------------------------------------------------------
    # Single or multiple ips found in scan?
    # -------------------------------------------------------------------------
    for ip in found_ip:
        output.output(
            f"Found ip: {ip}",
            "i"
        )
        output.output(
            f"Attempting to connect to VM on: {ip}",
            "i"
            )

        ssh = SSHConnection(
                host=ip,
                username=vc["ci_username"],
                key_filename=vc["vm_keyfile"],
            )

        vm_connect_flag, vm_connect_message = ssh.connect()
        output.output(
            vm_connect_message,
            type="s" if vm_connect_flag else "e",
            exit_on_error=True if len(found_ip) == 1 else False
            )

        result = ssh.run("hostname")
        if result['stdout'].strip('\n') == vc['name']:
            break

    ssh_config = {
        key.removeprefix("ssh_"): value
        for key, value in vc.items()
        if key.startswith("ssh_")
    }
    check_message = host.check_sshd_config(
            ssh_config,
            vc['sshd_searchstring'],
            vc['sshd_config_path'],
            vc['sshd_custom_config']
        )
    for line in check_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    if len(check_message) > 5:
        output.output(
            "Rechecking SSHD config",
            "i"
        )
        sshd_success = host.check_sshd_config(
            ssh_config,
            vc['sshd_searchstring'],
            vc['sshd_config_path'],
            vc['sshd_custom_config']
        )
        for line in sshd_success:
            output.output(
                f"{line[1]}",
                f"{line[2]}"
            )

    # Ensure QEMU agent on the guest
    steps = host.ensure_qemu_guest_agent_on_guest(ssh)
    for ok, msg, lvl in steps:
        output.output(msg, lvl)

    flag, message = ssh.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)

    output.output()
    output.output("Closing SSH", type="h")
    output.output()

    flag, message = host.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
    output.output()
