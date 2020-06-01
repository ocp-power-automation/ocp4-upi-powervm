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

variable "install_status" {}
variable "cluster_id" {}

variable "bastion_ip" {}
variable "bastion_id" {}

variable "storage_type" {}
variable "storageclass_name" {}
variable "volume_size" {}
variable "volume_storage_template" {}

variable "rhel_username" {}
variable "private_key" {}
variable "ssh_agent" {}
variable "jump_host" { default = "" }
