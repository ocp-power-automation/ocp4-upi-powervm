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

data "openstack_networking_network_v2" "network" {
    name        = var.network_name
}

data "openstack_networking_subnet_v2" "subnet" {
    network_id  = data.openstack_networking_network_v2.network.id
}

resource "openstack_networking_port_v2" "bootstrap_port" {
    name = "${var.cluster_id}-bootstrap-port"
    network_id  = data.openstack_networking_network_v2.network.id
    admin_state_up = "true"
    dynamic "binding" {
        for_each = local.bindings
        content {
            vnic_type = binding.value["vnic_type"]
            profile   = binding.value["profile"]
        }
    }
}

resource "openstack_networking_port_v2" "master_port" {
    count           = var.master_count
    name            = "${var.cluster_id}-master-port-${count.index}"
    network_id      = data.openstack_networking_network_v2.network.id
    admin_state_up  = "true"
    dynamic "binding" {
        for_each = local.bindings
        content {
            vnic_type = binding.value["vnic_type"]
            profile   = binding.value["profile"]
        }
    }
}

resource "openstack_networking_port_v2" "worker_port" {
    count           = var.worker_count
    name            = "${var.cluster_id}-worker-port-${count.index}"
    network_id      = data.openstack_networking_network_v2.network.id
    admin_state_up  = "true"
    dynamic "binding" {
        for_each = local.bindings
        content {
            vnic_type = binding.value["vnic_type"]
            profile   = binding.value["profile"]
        }
    }
}

locals {
   sriov   = <<EOF
   {
       "delete_with_instance": 1,
       "vnic_required_vfs": 1,
       "capacity": 0.02,
       "vlan_type": "allowed"
   }
   EOF
   bindings = var.network_type == "SRIOV" ? [{vnic_type = "direct", profile = local.sriov }] : []
}
