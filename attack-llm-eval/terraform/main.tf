# ===========================================================================
# Downloads: LXC template + cloud image
# ===========================================================================
resource "proxmox_virtual_environment_download_file" "ct_template" {
  content_type = "vztmpl"
  datastore_id = var.template_datastore_id
  node_name    = var.pve_node_name
  url          = var.ct_template_url
  overwrite    = false
}

resource "proxmox_virtual_environment_download_file" "cloud_image" {
  content_type = "iso" # cloud images are stored under the iso content type
  datastore_id = var.template_datastore_id
  node_name    = var.pve_node_name
  url          = var.cloud_image_url
  file_name    = "noble-server-cloudimg-amd64.img"
  overwrite    = false
}

# ===========================================================================
# Ollama / analysis container (LXC)
# ===========================================================================
resource "proxmox_virtual_environment_container" "ollama" {
  node_name     = var.pve_node_name
  vm_id         = var.ollama_vm_id
  unprivileged  = true
  start_on_boot = true

  cpu {
    cores = var.ollama_cores
  }

  memory {
    dedicated = var.ollama_memory_mb
    swap      = 512
  }

  disk {
    datastore_id = var.datastore_id
    size         = var.ollama_disk_gb
  }

  operating_system {
    template_file_id = proxmox_virtual_environment_download_file.ct_template.id
    type             = var.ct_os_type
  }

  network_interface {
    name   = "eth0"
    bridge = var.mgmt_bridge
  }

  initialization {
    hostname = var.ollama_hostname

    ip_config {
      ipv4 {
        address = var.ollama_ip_cidr
        gateway = var.ollama_ip_cidr == "dhcp" ? null : var.ollama_gateway
      }
    }

    user_account {
      keys = [trimspace(var.ssh_public_key)]
    }
  }

  # Nesting lets systemd services (like ollama) behave well inside the CT.
  features {
    nesting = true
  }

  startup {
    order = 1
  }
}

# Provisioning is done via a separate null_resource so it re-runs cleanly and
# does not block container creation if SSH is briefly unavailable.
resource "terraform_data" "provision_ollama" {
  count = var.provision_ollama ? 1 : 0

  depends_on = [proxmox_virtual_environment_container.ollama]

  # Re-run provisioning if the model list or core count changes.
  triggers_replace = {
    models = join(",", var.ollama_models)
    cores  = var.ollama_cores
  }

  connection {
    type        = "ssh"
    host        = var.ollama_ip_address
    user        = "root"
    private_key = file(var.ssh_private_key_file)
    timeout     = "4m"
  }

  provisioner "file" {
    content = templatefile("${path.module}/scripts/setup-ollama.sh.tftpl", {
      models = var.ollama_models
      cores  = var.ollama_cores
    })
    destination = "/root/setup-ollama.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /root/setup-ollama.sh",
      "bash /root/setup-ollama.sh",
    ]
  }
}

# ===========================================================================
# Attack lab VM
# ===========================================================================
# Cloud-init snippet (user-data) uploaded to a snippets-enabled datastore.
resource "proxmox_virtual_environment_file" "lab_user_data" {
  content_type = "snippets"
  datastore_id = var.snippet_datastore_id
  node_name    = var.pve_node_name

  source_raw {
    data = templatefile("${path.module}/cloud-init/lab-user-data.yaml.tftpl", {
      username   = var.lab_username
      ssh_key    = trimspace(var.ssh_public_key)
      hostname   = var.lab_name
    })
    file_name = "${var.lab_name}-user-data.yaml"
  }
}

resource "proxmox_virtual_environment_vm" "lab" {
  node_name = var.pve_node_name
  vm_id     = var.lab_vm_id
  name      = var.lab_name
  tags      = ["attack-lab", "isolate-me"]

  # qemu-guest-agent (installed via cloud-init) lets TF read the VM's IP.
  agent {
    enabled = true
  }

  cpu {
    cores = var.lab_cores
    type  = "host"
  }

  memory {
    dedicated = var.lab_memory_mb
  }

  disk {
    datastore_id = var.datastore_id
    file_id      = proxmox_virtual_environment_download_file.cloud_image.id
    interface    = "scsi0"
    size         = var.lab_disk_gb
  }

  network_device {
    bridge = var.lab_bridge
  }

  operating_system {
    type = "l26"
  }

  initialization {
    datastore_id      = var.datastore_id
    user_data_file_id = proxmox_virtual_environment_file.lab_user_data.id

    ip_config {
      ipv4 {
        address = var.lab_ip_cidr
        gateway = var.lab_ip_cidr == "dhcp" ? null : var.lab_gateway
      }
    }
  }

  startup {
    order = 2
  }
}
