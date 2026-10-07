terraform {
  required_version = ">= 1.5.0"

  required_providers {
    proxmox = {
      source = "bpg/proxmox"
      # Current series as of this writing is 0.111.x (supports PVE 8.x/9.x).
      # 0.x minors can break; bump deliberately and re-check the schema at
      # https://registry.terraform.io/providers/bpg/proxmox/latest/docs
      version = ">= 0.111.0, < 1.0.0"
    }
  }
}
