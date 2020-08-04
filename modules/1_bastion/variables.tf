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
variable "connection_timeout" {}
variable "jump_host" {}

variable "rhel_subscription_username" {}
variable "rhel_subscription_password" {}

variable "storage_type" {}
variable "volume_size" {}
variable "volume_storage_template" {}

variable "setup_squid_proxy" {}
variable "proxy" {}
