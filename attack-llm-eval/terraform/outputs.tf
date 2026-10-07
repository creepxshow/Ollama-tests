output "ollama_container_id" {
  value       = proxmox_virtual_environment_container.ollama.vm_id
  description = "LXC ID of the Ollama/analysis container"
}

output "ollama_ip" {
  value       = var.ollama_ip_address != "" ? var.ollama_ip_address : "check: pct exec ${var.ollama_vm_id} -- ip a"
  description = "Ollama container IP (point the harness here with --host http://<ip>:11434)"
}

output "lab_vm_id" {
  value       = proxmox_virtual_environment_vm.lab.vm_id
  description = "VM ID of the attack lab"
}

output "lab_vm_ipv4" {
  value       = try(proxmox_virtual_environment_vm.lab.ipv4_addresses, [])
  description = "Lab VM IPv4 addresses (populated once the guest agent reports in)"
}

output "next_steps" {
  value = <<-EOT
    1. Ollama: curl http://${var.ollama_ip_address}:11434/api/version
       Copy the harness:  scp -r ../  root@${var.ollama_ip_address}:/opt/attack-llm-eval
    2. Lab VM: SSH in as ${var.lab_username}, run collect_sysmon.sh install,
       then ISOLATE it (internal bridge or PVE firewall) before any atomics.
  EOT
}
