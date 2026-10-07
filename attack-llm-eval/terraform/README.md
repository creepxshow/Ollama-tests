# Terraform: Proxmox infra for attack-llm-eval

Provisions the two guests from the sizing discussion on one Proxmox host:

- **Ollama / analysis LXC** (`vmid 110`) — unprivileged Debian container, CPU-only
  Ollama with the keep-alive/thread tuning pre-applied and your models pulled.
- **Attack lab VM** (`vmid 120`) — Ubuntu 24.04 cloud image, a full VM (needs its
  own kernel for Sysmon's eBPF; needs isolation + snapshots for atomics).

Uses the `bpg/proxmox` provider (the maintained community standard).

## Prerequisites

1. **Terraform ≥ 1.5** or OpenTofu ≥ 1.6 on your workstation.
2. **A Proxmox API token.** In the PVE UI: Datacenter → Permissions → API Tokens.
   Create one for a user with VM/CT create rights (simplest: a token for `root@pam`
   with "Privilege Separation" unchecked, in a homelab). Note the full
   `user@realm!tokenid=secret` string.
3. **SSH to the node.** The provider uploads the cloud-init snippet over SSH, so
   your key must reach the node as `root` (agent or key file). Also ensure the
   `local` datastore has the **snippets** content type enabled
   (Datacenter → Storage → local → Edit → Content → tick *Snippets*).
4. **A thin-provisioned disk store** (`local-lvm` or a ZFS pool) so the 32 GB
   container disk only consumes what it uses.

## Deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # fill in endpoint, token, keys, IPs

terraform init
terraform plan                  # review
terraform apply
```

First apply downloads a CT template and the Ubuntu cloud image (a few hundred
MB), creates both guests, then SSHes into the container to install Ollama and
pull your models. The model pull is the slow part; watch it with
`terraform apply` output or `pct exec 110 -- ollama list`.

## After apply

```bash
terraform output next_steps
```

- **Analysis box:** copy the harness to the container and run it there, or run
  the Python anywhere and point it at the container:
  ```bash
  python -m attack_llm_eval.run --host http://192.168.1.50:11434 ...
  ```
- **Lab VM:** SSH in, install Sysmon (`collect_sysmon.sh install`), snapshot,
  then **isolate it** before running any atomics.

## Isolating the lab VM (do this before attacks)

The lab defaults to `vmbr0` so cloud-init can install packages from the
internet. That is fine for setup, **not** for running offensive atomics. Before
you run anything from `atomic_runbook.md`, pick one:

- **Internal bridge (cleanest):** in the PVE UI create a Linux bridge with *no*
  bridge ports (e.g. `vmbr1`), set `lab_bridge = "vmbr1"`, `terraform apply`,
  and give the VM a static address with no gateway. It can still talk to other
  guests on `vmbr1` (handy: run a local HTTP server there for the T1105 atomic)
  but has no route off-box.
- **PVE firewall:** enable the firewall on the VM's NIC and add egress rules
  that drop traffic to your LAN/RFC1918 and the internet, allowing only what a
  given test needs.

This is intentionally a manual/GUI step rather than Terraform: creating or
editing node networking via the provider can lock you out of the host if a
bridge is misconfigured, which isn't worth the risk for a one-time setup.

## Teardown

```bash
terraform destroy
```

Snapshots you took on the lab VM outside Terraform are not tracked by state;
remove them in the UI if `destroy` complains about the VM being locked.

## Gotchas

- **Static IP for the container.** Provisioning SSHes to `ollama_ip_address`.
  With DHCP, Terraform can't know the address at plan time — set a static IP, or
  set `provision_ollama = false` and install Ollama by hand (run
  `scripts/setup-ollama.sh.tftpl`'s commands).
- **Snippets datastore.** If apply fails uploading `*-user-data.yaml`, the
  target datastore doesn't have the Snippets content type enabled (see above).
- **Provider auth.** The provider needs *both* the API token (for most
  resources) and node SSH (for the snippet upload). Missing SSH shows up as a
  file-upload error on the lab VM resource.
- **CT template URL** goes stale as point releases change. If the download 404s,
  grab the current filename from `pveam available --section system` and update
  `ct_template_url`.
- **Re-pulling models.** Changing `ollama_models` re-triggers the provisioner,
  which pulls any new models (existing ones are cached).
