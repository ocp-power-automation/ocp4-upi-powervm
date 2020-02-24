output "bootstrap_port_id" {
    value = openstack_networking_port_v2.bootstrap_port.id
}

output "master_port_ids" {
    value = openstack_networking_port_v2.master_port.*.id
}

output "worker_port_ids" {
    value = openstack_networking_port_v2.worker_port.*.id
}