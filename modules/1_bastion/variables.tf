variable "cluster_domain" {
  default   = "example.com"
}
variable "cluster_id" {
  default   = "test-ocp"
}
variable "bastion" {
    # only one node is supported
    default = {
        instance_type = "m1.xlarge"
        image_id = "daa5d3f4-ab66-4b2d-9f3d-77bd61774419"
    }
}
variable "network_name" {}
variable "scg_id" {}
variable "openstack_availability_zone" {}

variable "rhel_username" {}
variable "private_key" {}
variable "public_key" {}
variable "create_keypair" {}
variable "keypair_name" {}
variable "ssh_agent" {}

variable "rhel_subscription_username" {}
variable "rhel_subscription_password" {}
