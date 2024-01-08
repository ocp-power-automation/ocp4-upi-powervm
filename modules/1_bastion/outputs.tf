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

output "bastion_ip" {
  depends_on = [null_resource.bastion_packages, null_resource.setup_nfs_disk]
  value      = var.pub_network_name == "" ? openstack_compute_instance_v2.bastion.*.access_ip_v4 : [openstack_compute_instance_v2.bastion[0].network[1].fixed_ip_v4]
}


output "pub_bastion_ip" {
  depends_on = [null_resource.bastion_packages, null_resource.setup_nfs_disk]
  value      = var.pub_network_name == "" ? "" : openstack_compute_instance_v2.bastion[0].access_ip_v4
}
