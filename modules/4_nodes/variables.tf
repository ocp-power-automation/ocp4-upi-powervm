variable "bootstrap_ign_url" {}
variable "master_ign_url" {}
variable "worker_ign_url" {}
variable "bastion_ip" {}
variable "cluster_domain" {}
variable "cluster_id" {}

variable "bootstrap" {
    # only one node is supported
    default = {
        instance_type = "m1.xlarge"
        # rhcos image id
        image_id      = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
        count = 1
    }
}
variable "master" {
    default = {
        instance_type = "m1.xlarge"
        # rhcos image id
        image_id      = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
        count = 3
    }
}
variable "worker" {
    default = {
        instance_type = "m1.xlarge"
        # rhcos image id
        image_id      = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
        count = 2
    }
}

variable "openstack_availability_zone" {}

variable "bootstrap_port_id" {}
variable "master_port_ids" {}
variable "worker_port_ids" {}
