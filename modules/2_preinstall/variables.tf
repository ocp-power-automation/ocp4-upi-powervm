
variable "cluster_domain" {
  default   = "example.com"
}
variable "cluster_id" {
  default   = "test-ocp"
}

variable "bastion_ip" {}
variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}

variable "public_key" {}
variable "pull_secret" {}
variable "master_count" {}

variable "openshift_install_tarball" {}
variable "release_image_override" {}
