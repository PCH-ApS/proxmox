**Welcome to My Proxmox Automation Repo!**

I’ve always wanted to automate as much of my infrastructure as possible with code. The thing is, I don’t make changes to my infrastructure very often, and when I do, I tend to forget to update my documentation. Sound familiar? That’s where this idea started.

Initially, I planned to focus on bootstrapping my Proxmox servers. My thought was, “What if I need to start from scratch and rebuild everything?” So, the plan was to begin with the hypervisor and build everything up from there.

But then reality set in. After weighing the effort vs. the benefit (at least for my needs), I decided to simplify. Instead of over-engineering the setup, I opted for a quick, straightforward, “next-next-next” Proxmox installation. From there, I could tweak it to fit my needs using a script and a config file.

With Proxmox up and running, the next step was creating a VM template. The goal? To spin up VMs from these templates that come prepped with SSH keys and are ready for configuration using Ansible playbooks. Again, I kept it simple and repeatable by relying on scripts and config files.

The idea is to make it easy to rebuild everything from scratch, up to this point, as long as I have the configs handy. I sometimes lose track of where I am during a project and decide to start over—this approach makes that process painless.

This repo is my way of sharing that approach with anyone who might find it useful. I hope it helps you simplify your infrastructure setup as much as I hope it will for me!
