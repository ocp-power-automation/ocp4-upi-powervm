################################################################
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Licensed Materials - Property of IBM
#
# ©Copyright IBM Corp. 2020
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

variable "cluster_domain" {
  default   = "example.com"
}
variable "cluster_id" {
  default   = "test-ocp"
}

variable "dns_forwarders" {
    default   = "8.8.8.8; 9.9.9.9"
}

variable "gateway_ip" {}
variable "cidr" {}
variable "allocation_pools" {}

variable "bastion_ip" {}
variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}
variable "connection_timeout" {}
variable "jump_host" {}

variable "bootstrap_port_ip" {}
variable "master_port_ips" {}
variable "worker_port_ips" {}

variable "bootstrap_mac" {}
variable "master_macs" {}
variable "worker_macs" {}

variable "openshift_client_tarball" {}
variable "openshift_install_tarball" {}

variable "enable_local_registry" {}
variable "local_registry_image" {}
variable "ocp_release_tag" {}

variable "helpernode_repo" {}
variable "helpernode_tag" {}

variable "ansible_extra_options" {}

variable "chrony_config" { default = true }
variable "chrony_config_servers" {}
