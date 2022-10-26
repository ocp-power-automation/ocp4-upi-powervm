##################v##############################################
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Licensed Materials - Property of IBM
#
# ©Copyright IBM Corp. 2022
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

variable "cluster_domain" {
  default = "example.com"
}
variable "cluster_id" {
  default = "test-ocp"
}

variable "bastion_vip" {}
variable "bastion_ip" {}
variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}
variable "connection_timeout" {}
variable "jump_host" {}

variable "worker_ips" {}


variable "ansible_extra_options" {}


variable "upgrade_version" {}
variable "upgrade_channel" {}
variable "upgrade_image" {}
variable "upgrade_pause_time" {}
variable "upgrade_delay_time" {}

variable "eus_upgrade_version" {}
variable "eus_upgrade_channel" {}
variable "eus_upgrade_image" {}
variable "eus_upstream" {}
