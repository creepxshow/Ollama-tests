# ---------------------------------------------------------------------------
# Proxmox connection
# ---------------------------------------------------------------------------
variable "pve_endpoint" {
  type        = string
  description = "Proxmox API URL, e.g. https://192.168.1.10:8006/"
}

variable "pve_api_token" {
  type        = string
  sensitive   = true
  description = "API token: user@realm!tokenid=secret"
}

variable "pve_node_name" {
  type        = string
  default     = "pve"
  description = "Target Proxmox node name"
}

variable "pve_insecure" {
  type        = bool
  default     = true
  description = "Skip TLS verify (self-signed PVE cert)"
}

variable "pve_ssh_username" {
  type    = string
  default = "root"
}

variable "pve_ssh_agent" {
  type    = bool
  default = true
}

# ---------------------------------------------------------------------------
# SSH keys for the guests
# ---------------------------------------------------------------------------
variable "ssh_public_key" {
  type        = string
  description = "Public key injected into both guests (authorized_keys)"
}

variable "ssh_private_key_file" {
  type        = string
  description = "Path to the matching private key, used to provision the Ollama container"
  default     = "~/.ssh/id_ed25519"
}

# ---------------------------------------------------------------------------
# Storage / networking defaults
# ---------------------------------------------------------------------------
variable "datastore_id" {
  type        = string
  default     = "local-lvm"
  description = "Datastore for guest root disks (thin LVM or ZFS recommended)"
}

variable "snippet_datastore_id" {
  type        = string
  default     = "local"
  description = "Datastore that has the 'snippets' content type enabled (for cloud-init)"
}

variable "template_datastore_id" {
  type        = string
  default     = "local"
  description = "Datastore for downloaded CT templates and cloud images"
}

variable "mgmt_bridge" {
  type        = string
  default     = "vmbr0"
  description = "Bridge on your management/LAN network"
}

variable "lab_bridge" {
  type        = string
  default     = "vmbr0"
  description = <<-EOT
    Bridge for the attack lab VM. Defaults to the management bridge so
    cloud-init can reach the internet to install Sysmon/ART. ISOLATE this VM
    (move to an internal-only bridge, or apply a restrictive PVE firewall)
    BEFORE running any atomics. See README.
  EOT
}

# ---------------------------------------------------------------------------
# Ollama / analysis container
# ---------------------------------------------------------------------------
variable "ollama_vm_id" {
  type    = number
  default = 110
}

variable "ollama_hostname" {
  type    = string
  default = "ollama"
}

variable "ollama_cores" {
  type        = number
  default     = 4
  description = "vCPU for the container. On a 4-thread i5-6500T, give it all 4 and shut the lab VM down during analysis."
}

variable "ollama_memory_mb" {
  type        = number
  default     = 16384
  description = "RAM in MB. Beyond model size this is page-cache for weights."
}

variable "ollama_disk_gb" {
  type        = number
  default     = 32
  description = "Root disk. ~8GB system+tooling, ~20GB model headroom, slack."
}

variable "ollama_ip_cidr" {
  type        = string
  default     = "dhcp"
  description = "Static IP as CIDR (e.g. 192.168.1.50/24) or 'dhcp'. Static is strongly recommended so provisioning can SSH in deterministically."
}

variable "ollama_gateway" {
  type    = string
  default = ""
  description = "Gateway for a static IP (e.g. 192.168.1.1). Leave empty for dhcp."
}

variable "ollama_ip_address" {
  type        = string
  default     = ""
  description = "Bare IP (no CIDR) used by the provisioner SSH connection. Set this to the same address as ollama_ip_cidr when using a static IP."
}

variable "ct_template_url" {
  type        = string
  default     = "http://download.proxmox.com/images/system/debian-12-standard_12.7-1_amd64.tar.zst"
  description = "LXC template to download"
}

variable "ct_os_type" {
  type    = string
  default = "debian"
}

variable "ollama_models" {
  type        = list(string)
  default     = ["llama3.2:1b", "llama3.2:3b", "llama3.1:8b"]
  description = "Models pulled at provision time. Keep to small models on CPU-only hardware."
}

variable "provision_ollama" {
  type        = bool
  default     = true
  description = "Run the remote-exec that installs Ollama, tunes it, and pulls models. Set false to provision by hand."
}

# ---------------------------------------------------------------------------
# Attack lab VM
# ---------------------------------------------------------------------------
variable "lab_vm_id" {
  type    = number
  default = 120
}

variable "lab_name" {
  type    = string
  default = "attack-lab"
}

variable "lab_cores" {
  type    = number
  default = 2
}

variable "lab_memory_mb" {
  type    = number
  default = 4096
}

variable "lab_disk_gb" {
  type    = number
  default = 40
}

variable "lab_ip_cidr" {
  type        = string
  default     = "dhcp"
  description = "Static CIDR or 'dhcp' for the lab VM"
}

variable "lab_gateway" {
  type    = string
  default = ""
}

variable "lab_username" {
  type    = string
  default = "labadmin"
}

variable "cloud_image_url" {
  type        = string
  default     = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
  description = "Ubuntu cloud image for the lab VM (24.04 LTS = good eBPF/Sysmon support)"
}
