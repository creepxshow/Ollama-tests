provider "proxmox" {
  endpoint = var.pve_endpoint        # e.g. "https://192.168.1.10:8006/"
  api_token = var.pve_api_token      # "user@pam!tokenid=uuid"
  insecure = var.pve_insecure        # true for self-signed PVE certs

  # The bpg provider needs SSH to the node for some operations (uploading
  # cloud-init snippets, certain file operations). Uses the node's root/sudo
  # user. Key auth via your agent or a key file is recommended.
  ssh {
    agent    = var.pve_ssh_agent
    username = var.pve_ssh_username   # usually "root"
    # If not using an agent, uncomment and set a key:
    # private_key = file(var.pve_ssh_private_key_file)
  }
}
