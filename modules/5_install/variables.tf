variable "cluster_domain" {
  default   = "example.com"
}
variable "cluster_id" {
  default   = "test-ocp"
}

variable "dns_forwarders" {
    default   = "8.8.8.8; 9.9.9.9"
}
variable gateway_ip {}
variable cidr {}
variable allocation_pools {}

variable "bastion_ip" {}
variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}

variable "bootstrap_ip" {}
variable "master_ips" {}
variable "worker_ips" {}

variable bootstrap_mac {}
variable master_macs {}
variable worker_macs {}

variable "openshift_client_tarball" {}
variable "openshift_install_tarball" {}

variable "public_key" {}
variable "pull_secret" {}
variable "master_count" {}
variable "release_image_override" {}

variable helpernode_tag { default = "master" }
variable "storage_type" {}
variable "log_level" {}
