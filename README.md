**Welcome to My Proxmox Automation Repo!**

The purpose of this repository is to automate Proxmox tasks.
## Preface
I want to move out of the cloud services that I have used for the last many years, and I have decided to build up my own infrastructure again - to support my business.

I tend to forget how I do tasks I don´t do very often, and therefor I have decided that this time I will try and automate as much as I can and build it as infrastructure as code to the extent i am capable of.

Much can probably be automated much more clever (and better) then what I am doing in this repo. This is what I have come up with - and I have used AI chatbots along the way.
I haven´t been in a developer role for almost 20 years, and there is lots I have to relearn. I have a pretty clear vision of what I want to achieve and I have used AI to help me get there.

## The idea
My idea is to be able to spin up my infrastructure fast with code. Both to be able to handle the initial spin up, and when something goes horribly wrong and I have to recreate everything. Then next thing I want is to make it in a way that I can use the code to check the active configuration - making sure the environment is consistent with what I want.

This repository shall enable me to:
- deploy a Proxmox host, configure it, and make it ready for (Linux) servers to be deployed on to the host.
- deploy servers on the host

All should be done with IaC and config files for the host and the servers. This is the initial approach.

## The goal
Eventually I hope to get to a point where I can have one or more pipelines running, creating and maintaining servers on the host, depending on the config files provided. I would like to bring my infrastructure up to a point where I can benefit from something like Ansible to maintain the infrastructure. I would like to be able to just create a new config file, upload it to the repo and then wait a few minutes for the server to be available, and have Ansible finish the configuration. For now the Ansible part is just a dream.....

### Proxmox
I had a look at bootstapping Promox. I decided that the effort needed to get it to work, was not worth it, compared to a next, next, next installation of Proxmox that I then could modify with code and config files.
Please read the [Promox installation (a prerequisite)](https://github.com/PCH-ApS/proxmox/blob/main/md/Promox%20installation%20(a%20prerequisite).md) to prepare the Proxmox host

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
