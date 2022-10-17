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
# ©Copyright IBM Corp. 2022
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

variable "bastion_ip" {}
variable "cluster_id" {}

variable "master" {
  default = {
    instance_type = "m1.xlarge"
    # rhcos image id
    image_id = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
    count    = 3
  }
}

variable "scg_id" {}
variable "openstack_availability_zone" {}

variable "master_port_ids" {}

variable "mount_etcd_ramdisk" {}

variable "install_status" {}
