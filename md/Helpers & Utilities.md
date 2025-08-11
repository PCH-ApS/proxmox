# Helpers & Utilities

This repo includes small, focused helper classes. Below is a quick overview of what they do and how to call them.

## `OutputHandler` (lib/output_handler.py)

**Purpose:** unified terminal + logfile output with simple levels and optional colors; supports desktop notifications on Linux.

**Init**
```python
from lib.output_handler import OutputHandler
out = OutputHandler(logfile="logs/run.log", enable_colors=True)
```

**Key usage**
```python
out.output("Heading", type="h")      # heading
out.output("Info message", type="i") # info
out.output("Success", type="s")      # success
out.output("Warning", type="w")      # warning
out.output("Error", type="e", exit_on_error=True)  # error + exit
out.notify("Build done", "Template created")       # notify-send
```

**Prereqs:** if `logfile` has a directory, it will be created. `notify` uses `notify-send` if available.

---

## `CheckFiles` (lib/check_files_handler.py)

**Purpose:** validate that a file exists, is readable, and looks like YAML.

**Init & calls**
```python
from lib.check_files_handler import CheckFiles
chk = CheckFiles("/path/to/file.yaml")
if not chk.check():
    print(chk.errors)  # list of messages
```

**Prereqs:** path must exist where called. Sets flags: `file_exists`, `file_readable`, `file_is_yaml`, `valid`.

---

## `LoaderNoDuplicates` (lib/yaml_config_loader.py)

**Purpose:** YAML loader that **rejects duplicate keys** — safer configs.

**Usage**
```python
import yaml
from lib.yaml_config_loader import LoaderNoDuplicates
with open("config.yaml") as fh:
    cfg = yaml.load(fh.read(), Loader=LoaderNoDuplicates)
```

---

## `SSHConnection` (lib/ssh_handler.py)

**Purpose:** thin wrapper around `paramiko` to open, run, and close SSH connections.

**Init & lifecycle**
```python
from lib.ssh_handler import SSHConnection
ssh = SSHConnection(host="10.0.0.2", username="root", key_filename="~/.ssh/id_rsa")
ok, msg = ssh.connect()
res = ssh.run("qm status 100")  # -> dict with stdout/stderr/exit_code
ssh.close()
```

**Prereqs:** valid credentials; if using keys ensure file permissions are correct.

---

## `RemoteHost` (lib/remote_host.py)

**Purpose:** type‑safe wrapper around any SSH‑like connection that provides `connect`, `run`, and `close`.

**Init**
```python
from lib.ssh_handler import SSHConnection
from lib.remote_host import RemoteHost

# Create SSH transport and wrap it in RemoteHost
ssh = SSHConnection(host="10.0.0.2", username="root", key_filename="~/.ssh/id_rsa")
host = RemoteHost(ssh)

# --- Lifecycle -------------------------------------------------------------
ok, msg = host.connect()
print("connect:", ok, msg)

# --- Identity / sanity -----------------------------------------------------
ok, name = host.get_hostname()
print("hostname:", ok, name)

# --- Authorized keys management (idempotent) -------------------------------
results = host.check_ssh_keys([
    "ssh-ed25519 AAAAC3Nz... user1@laptop",
    "ssh-rsa AAAAB3Nza...    ops@example"
])
for ok, msg, lvl in results:
    print(lvl, ok, msg)

# --- Simple file edits -----------------------------------------------------
ok, msg = host.add_to_file("net.ipv4.ip_forward=1", "/etc/sysctl.conf")
print("add_to_file:", ok, msg)

ok, msg = host.remove_line_with_content("net.ipv4.ip_forward=1", "/etc/sysctl.conf")
print("remove_line_with_content:", ok, msg)

# Ensure a few lines exist in a file (append only if missing)
lines_out = host.ensure_lines_in_file(
    lines=[
        "PermitRootLogin prohibit-password",
        "PasswordAuthentication no",
    ],
    path="/etc/ssh/sshd_config",
    user="root"
)
for ok, msg, lvl in lines_out:
    print(lvl, ok, msg)

# --- SSHD config introspection --------------------------------------------
ok, active = host.get_active_sshd_config(user="root")
if ok:
    desired = {
        "permitrootlogin": "prohibit-password",
        "passwordauthentication": "no",
        "challengeresponseauthentication": "no",
    }
    missing = host.get_missing_sshd_keys(active, desired)
    wrong = host.get_wrong_value_sshd_keys(active, desired)
    print("sshd missing keys:", missing)
    print("sshd wrong-valued keys:", wrong)
else:
    print("failed to read active sshd config:", active.get("error"))

# Optionally comment out a parameter (backup auto-created)
did_comment = host.comment_out_param_in_file("GSSAPIAuthentication", "/etc/ssh/sshd_config")
print("comment_out_param_in_file:", did_comment)

# Check if a parameter is explicitly set (non-commented)
print("PasswordAuthentication explicitly set?",
      host.is_param_explicitly_set("PasswordAuthentication", "/etc/ssh/sshd_config"))

# --- Include chains / config discovery ------------------------------------
ok, included = host.search_configfile("Include", "/etc/ssh/sshd_config")
print("search_configfile:", ok, included)

all_files = host.get_all_config_files("Include", "/etc/ssh/sshd_config")
print("get_all_config_files:", all_files)

# Resolve a wildcard on the remote host
ok, paths = host.resolve_wildcard_path("/etc/ssh/sshd_config*")
print("resolve_wildcard_path:", ok, paths)

# --- User management -------------------------------------------------------
pw_out = host.change_pwd(user="deploy", new_password="S3cure!pass", treat_user_as_root=False)
for ok, msg, lvl in pw_out:
    print(lvl, ok, msg)

# --- Reboot / reconnect flows (static helpers) -----------------------------
# NOTE: This will reboot the target. Uncomment when you actually need it.
# reboot_log = RemoteHost.reboot_and_reconnect(ssh=ssh, wait_time=10, timeout=180, user="root")
# for ok, msg, lvl in reboot_log: print(lvl, ok, msg)

# Or, if a service restart cut your SSH session and you just want to retry:
reconnect_log = RemoteHost.reconnect(ssh=ssh, wait_time=5, timeout=60)
for ok, msg, lvl in reconnect_log:
    print(lvl, ok, msg)

# --- Guest VM helper (run from inside a guest via its own SSH) ------------
# If you happen to have an SSH connection to a *guest*:
# guest_ssh = SSHConnection(host="10.0.1.50", username="ubuntu", key_filename="~/.ssh/id_rsa")
# guest_out = host.ensure_qemu_guest_agent_on_guest(guest_ssh)
# for ok, msg, lvl in guest_out: print(lvl, ok, msg)

# --- Raw command passthrough if needed ------------------------------------
res = host.run("uname -a")
print("run exit:", res["exit_code"])
print("stdout:", res["stdout"])
print("stderr:", res["stderr"])

# --- Cleanup ---------------------------------------------------------------
ok, msg = host.close()
print("close:", ok, msg)


```

---

## `ProxmoxHost` (lib/proxmox_host_handler.py)

**Purpose:** high‑level helpers to work with a Proxmox VE host over SSH. Combines many `qm` and system operations behind readable methods.

**Common calls (selection)**
```python
from lib.proxmox_host_handler import ProxmoxHost

host = ProxmoxHost(host="10.0.0.2", username="root", key_filename="~/.ssh/id_rsa")

# Connectivity & identity
ok, msg = host.change_hostname("pve01")  # may require reboot + reconnect

# Sanity checks
ok, msg = host.check_bridge_exists("vmbr0")
ok, msg = host.check_storage_exists("local-lvm")
ok, msg = host.is_vmid_in_use(101)
ok, msg = host.check_cpu_model_supported("x86-64-v2-AES")
ok, msg = host.validate_disk_slot("scsi0")

# VM operations
ok, msg = host.clone_vmid_if_missing(src_vmid=9000, dst_vmid=101, name="web-01")
ok, cfg = host.get_qm_config(101)
ok, msg = host.ensure_cloudinit_drive(101)
ok, msg = host.set_ci_network(101, bridge="vmbr0", model="virtio", vlan=30, mode="dhcp")

# Repo & UI
lines = host.check_pve_no_subscribtion()
lines = host.check_pve_enterprise()
lines = host.check_pve_ceph()
lines = host.check_pve_no_subscription_patch()

# Downloads
lines = host.download_iso_files(urls=[
  "https://example.org/debian.iso"
], path="/var/lib/vz/template/iso")
```

**Notes**
- Most methods return a tuple `(ok: bool, message: str)` or a list of lines to print.  
- For long‑running operations the scripts already handle result printing via `OutputHandler`.

---

## Validation schemas

Each `run_*.py` defaults to a schema file:
- **Host:** `config/host_config_validation.yaml`
- **Template:** `config/template_config_validation.yaml`
- **Guest:** `config/guest_config_validation.yaml`

You can override with `--validation <path>`.

> Heads‑up: In `create_template.py`, the default logfile is spelled `create_teamplate.log`. Consider renaming to `create_template.log` for consistency.
