output "bootstrap_ip" {
    value = openstack_compute_instance_v2.bootstrap.access_ip_v4
}

output "master_ips" {
    value = openstack_compute_instance_v2.master.*.access_ip_v4
}

output "worker_ips" {
    value = openstack_compute_instance_v2.worker.*.access_ip_v4
}
