**Welcome to My Proxmox Automation Repo!**

# Proxmox Automation

This is my personal take on automating infrastructure using Proxmox.

The aim is to create a clean and modern way to bring up virtual machines and templates using nothing more than YAML and SSH — no web UI clicks, no Proxmox API, and no guesswork. Just clear config and repeatable tooling.

While I’ve worked in tech for a long time, I haven’t been in a developer role for almost 20 years — and there’s a lot I’ve had to relearn. I have a clear vision of what I want to build, but I also knew I’d need help to explore what’s possible with modern Python. So I leaned on AI chatbots along the way: not to do the thinking for me, but to accelerate my learning, suggest better tooling, and guide my structure. 

Much of what’s in this repo can probably be automated more cleverly — or more “Pythonically” — than I’ve done it. But this is what I came up with, and it works for me. It’s readable, testable, and something I can build on.

This toolkit is intentionally focused on the **post-install state** of a Proxmox host. I did explore bootstrapping the OS and installing Proxmox programmatically — but decided that the complexity wasn’t worth it. Clicking through the standard installer (`Next`, `Next`, `Finish`) is fast and reliable. Once installed, this repo takes over: connecting to the host, configuring it, creating templates, and provisioning guests.

If you're using this project, make sure you've already installed Proxmox manually. See the [Proxmox Installation](https://pve.proxmox.com/wiki/Installation) docs or my own guide [Promox installation (a prerequisite)](https://github.com/PCH-ApS/proxmox/blob/main/md/Promox%20installation%20(a%20prerequisite).md) — this is a prerequisite for everything else here.

This toolkit is not intended to be the final layer of automation. Instead, it brings Proxmox hosts and guests to a known-good **baseline state** — the point where true Infrastructure-as-Code can take over. With hosts set up, templates in place, and guests provisioned consistently, tools like Ansible, Terraform, or SaltStack can handle configuration, service orchestration, and lifecycle management.

Think of this project as the **foundation layer**: automation that bootstraps your virtual infrastructure, so your real IaC tooling has something solid to build on.
## Scripts & Structure

This project uses modular scripts backed by schema-validated YAML files.
Each script targets a single layer of Proxmox automation.

| Script               | Role                                      |
|----------------------|-------------------------------------------|
| `configure_host.py`  | Prepares host (hostname, sshd, repos)     |
| `create_template.py` | Converts a cloud image into a VM template |
| `create_guest.py`    | Clones and configures a guest VM          |

See `/md/` folder for in-depth descriptions and workflows.

## Design Highlights

- **Idempotent**: Re-runs safely — only applies config diffs.
- **Schema-validated**: YAML configs validated by `cerberus`.
- **Modular & inspectable**: Small tools, readable logs.
- **SSH-only**: No Proxmox API or web UI needed.

## Example Guest Config (YAML)

```yaml
name: "test-server"
id: 8888
clone_id: 9001
vlan: 254
driver: virtio
bridge: vmbr0
memory: 2048
ci_network: dhcp
