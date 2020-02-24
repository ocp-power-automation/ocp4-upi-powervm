output "bootstrap_ign_url" {
    depends_on = [null_resource.ocp_ignition_update]
    value = "http://${var.bastion_ip}:8080/bootstrap.ign"
}

output "master_ign_url" {
    depends_on = [null_resource.ocp_ignition_update]
    value = "http://${var.bastion_ip}:8080/master.ign"
}

output "worker_ign_url" {
    depends_on = [null_resource.ocp_ignition_update]
    value = "http://${var.bastion_ip}:8080/worker.ign"
}
