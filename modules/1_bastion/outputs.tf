
output "bastion_ip" {
    depends_on = [null_resource.bastion_init]
    value = openstack_compute_instance_v2.bastion.access_ip_v4
}
