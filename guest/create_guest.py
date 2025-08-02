#!/usr/bin/env python3
import os
import sys
import argparse
import yaml
import shlex

from lib.output_handler import OutputHandler
from lib.check_files_handler import CheckFiles
from lib.yaml_config_loader import LoaderNoDuplicates
from cerberus import Validator
from lib.proxmox_host_handler import ProxmoxHost

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

    # Check config files
    check_files(args.config_file)
    check_files(args.validation_file)
    config_values = load_yaml_file(args.config_file)
    validation_rules = load_yaml_file(args.validation_file)
    v_config = validate_config(config_values, validation_rules)
    if not v_config:
        output.output(
            "Error retrieving config from yaml-files",
            "e",
            exit_on_error=True
            )
        return

    max_key_len = max(len(key) for key in v_config)
    for key in v_config:
        label = "set by user" if key in config_values else "using default"
        output.output(f"{key.ljust(max_key_len + 1)}: {label}", type="i")

    host = ProxmoxHost(
        host=v_config["v_host_ip"],
        username=v_config["v_host_username"],
        key_filename=v_config["v_host_keyfile"],
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

    output.output()
    output.output("Validating Proxmox prerequisites", type="h")
    output.output()

    ok, msg = host.is_vmid_in_use(v_config["v_clone_id"])
    output.output(
        f"Clone id exists. {v_config['v_clone_id']}",
        "s" if ok else "e",
        exit_on_error=not ok
        )

    output.output()
    output.output("Cloning new VM or updating existing VM", "h")
    output.output()

    ok, msg = host.clone_vmid_if_missing(
        v_config["v_clone_id"],
        v_config["v_id"]
        )
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    # --- Read current state ---
    ok, st = host.get_qm_status(v_config["v_id"])
    output.output(
        "Fetched qm status.",
        "s" if ok else "e",
        exit_on_error=not ok
        )

    ok, cfg = host.get_qm_config(v_config["v_id"])
    output.output(
        "Fetched qm config.",
        "s" if ok else "e",
        exit_on_error=not ok
        )

    # --- Plan changes (only apply diffs) ---
    vmid = v_config["v_id"]
    plan: list[tuple[str, str]] = []

    # name
    desired_name = shlex.quote(v_config["v_name"])
    if st.get("name") != v_config["v_name"]:
        plan.append((
            f"qm set {vmid} --name {desired_name}",
            f"Set name to {v_config['v_name']}"
            ))

    # cores
    if cfg.get("cores") != str(v_config["v_cores"]):
        plan.append((
            f"qm set {vmid} --cores {v_config['v_cores']}",
            f"Set cores to {v_config['v_cores']}"
            ))

    # memory
    if cfg.get("memory") != str(v_config["v_memory"]):
        plan.append((
            f"qm set {vmid} --memory {v_config['v_memory']}",
            f"Set memory to {v_config['v_memory']} MB"))

    # balloon
    desired_balloon = str(v_config["v_balloon"])
    if cfg.get("balloon") != desired_balloon:
        plan.append((
            f"qm set {vmid} --balloon {desired_balloon}",
            f"Set balloon to {desired_balloon}"
            ))

    # onboot
    desired_onboot = "1" if v_config["v_boot_start"] else "0"
    if cfg.get("onboot") != desired_onboot:
        plan.append((
            f"qm set {vmid} --onboot {desired_onboot}",
            f"Set onboot={desired_onboot}"
            ))

    # NIC (model + bridge + vlan tag)
    want_model = v_config["v_driver"]
    want_bridge = v_config["v_bridge"]
    want_tag = v_config["v_vlan"]
    current_net = host.parse_net_kv(cfg.get("net0", ""))
    need_net = (
        current_net.get("model") != want_model or
        current_net.get("bridge") != want_bridge or
        str(current_net.get("tag")) != str(want_tag)
    )
    if need_net:
        net_str = f"{want_model},bridge={want_bridge},tag={want_tag}"
        plan.append((
            f"qm set {vmid} --net0 {shlex.quote(net_str)}",
            f"Set net0 to {net_str}"
            ))

    # cloud-init user/pass/domain/dns/upgrade
    if (
        "v_ci_username" in v_config
        and cfg.get("ciuser") != v_config["v_ci_username"]
    ):
        plan.append((
            f"qm set {vmid} --ciuser "
            f"{shlex.quote(v_config['v_ci_username'])}",
            f"Set ciuser={v_config['v_ci_username']}"
        ))

    if "v_ci_password" in v_config:
        plan.append((
            f"qm set {vmid} --cipassword "
            f"{shlex.quote(v_config['v_ci_password'])}",
            "Set ci password"
        ))

    if (
        "v_ci_domain" in v_config
        and cfg.get("searchdomain") != v_config["v_ci_domain"]
    ):
        plan.append((
            f"qm set {vmid} --searchdomain "
            f"{shlex.quote(v_config['v_ci_domain'])}",
            f"Set searchdomain={v_config['v_ci_domain']}"
            ))

    if (
        "v_ci_dns_server" in v_config
        and cfg.get("nameserver") != v_config["v_ci_dns_server"]
    ):
        plan.append((
            f"qm set {vmid} --nameserver "
            f"{shlex.quote(v_config['v_ci_dns_server'])}",
            f"Set nameserver={v_config['v_ci_dns_server']}"
            ))

    # current value from `qm config` (usually '1' or '0')
    current = str(cfg.get("ciupgrade", "")).strip()

    # desired value from YAML (boolean) converted to '1'/'0'
    desired = host.bool(v_config.get("v_ci_upgrade"))

    if "v_ci_upgrade" in v_config and current != desired:
        plan.append((
            f"qm set {vmid} --ciupgrade {desired}",
            f"Set ciupgrade={desired}"
        ))

    # apply plan
    output.output()
    output.output("Applying configuration deltas", "h")
    output.output()
    for cmd, msg_ok in plan:
        run_or_die(host, cmd, msg_ok, "Failed to apply qm setting")

    # SSH public keys (list)
    if v_config.get("v_ci_publickey"):
        ok, msg = host.ensure_sshkeys(vmid, v_config["v_ci_publickey"])
        output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    ci_storage = v_config.get("v_local_storage")
    # make sure this exists in your YAML
    if ci_storage:
        steps = host.ensure_cloudinit_drive(
            vmid=vmid,
            storage=ci_storage,
            bus="ide",  # Proxmox commonly uses ide2 for CI
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
            "No 'v_local_storage' provided; skipping Cloud-Init drive attach.",
            "i"
            )

    # cloud-init networking
    if v_config["v_ci_network"].lower() == "dhcp":
        ok, msg = host.set_ci_network(vmid, "dhcp")
        output.output(msg, "s" if ok else "e", exit_on_error=not ok)
    else:
        ip = v_config.get("v_ci_ipaddress")
        gw = v_config.get("v_ci_gateway")
        cidr = v_config.get("v_ci_netmask", "").lstrip("/")
        # your YAML stores like '/24'
        ok, msg = host.set_ci_network(vmid, "static", ip=ip, gw=gw, cidr=cidr)
        output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    # regenerate cloud-init
    ok, msg = host.cloudinit_update(vmid)
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    # start VM
    output.output()
    output.output("Starting VM", "h")
    output.output()
    ok, msg = host.start_vm(vmid)
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    output.output()
    output.output("Closing SSH", type="h")
    output.output()
    flag, message = host.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
    output.output()
