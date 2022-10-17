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
  name = var.network_name
}

data "openstack_networking_subnet_v2" "subnet" {
  network_id = data.openstack_networking_network_v2.network.id
}

resource "openstack_networking_port_v2" "bastion_vip" {
  count = local.bastion_count > 1 ? 1 : 0

  name           = "${var.cluster_id}-bastion-vip"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = local.fixed_ip_v4
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

resource "openstack_networking_port_v2" "bastion_port" {
  count      = local.bastion_count
  depends_on = [openstack_networking_port_v2.bastion_vip]

  name           = "${var.cluster_id}-bastion-port-${count.index}"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = local.bastion_count == 1 ? local.fixed_ip_v4 : (length(local.bastion_ips) == 0 ? "" : local.bastion_ips[count.index])
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

resource "openstack_networking_port_v2" "bootstrap_port" {
  depends_on     = [openstack_networking_port_v2.bastion_port, openstack_networking_port_v2.bastion_vip]
  count          = local.bootstrap_count
  name           = "${var.cluster_id}-bootstrap-port"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = length(local.bootstrap_ips) == 0 ? "" : local.bootstrap_ips[count.index]
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

resource "openstack_networking_port_v2" "master_port" {
  depends_on     = [openstack_networking_port_v2.bastion_port, openstack_networking_port_v2.bastion_vip, openstack_networking_port_v2.bootstrap_port]
  count          = local.master_count
  name           = "${var.cluster_id}-master-port-${count.index}"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = length(local.master_ips) == 0 ? "" : local.master_ips[count.index]
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

resource "openstack_networking_port_v2" "worker_port" {
  depends_on     = [openstack_networking_port_v2.bastion_port, openstack_networking_port_v2.bastion_vip, openstack_networking_port_v2.bootstrap_port, openstack_networking_port_v2.master_port]
  count          = local.worker_count
  name           = "${var.cluster_id}-worker-port-${count.index}"
  network_id     = data.openstack_networking_network_v2.network.id
  admin_state_up = "true"
  fixed_ip {
    subnet_id  = data.openstack_networking_subnet_v2.subnet.id
    ip_address = length(local.worker_ips) == 0 ? "" : local.worker_ips[count.index]
  }
  dynamic "binding" {
    for_each = local.bindings
    content {
      vnic_type = binding.value["vnic_type"]
      profile   = binding.value["profile"]
    }
  }
}

locals {
  sriov    = <<EOF
   {
       "delete_with_instance": 1,
       "vnic_required_vfs": ${var.sriov_vnic_failover_vfs},
       "capacity": ${var.sriov_capacity},
       "vlan_type": "allowed"
   }
   EOF
  bindings = var.network_type == "SRIOV" ? [{ vnic_type = "direct", profile = local.sriov }] : []

  bastion_count   = lookup(var.bastion, "count", 1)
  fixed_ip_v4     = lookup(var.bastion, "fixed_ip_v4", "")
  bastion_ips     = lookup(var.bastion, "fixed_ips", [])
  bootstrap_count = var.bootstrap["count"]
  master_count    = var.master["count"]
  worker_count    = var.worker["count"]
  bootstrap_ips   = lookup(var.bootstrap, "fixed_ips", [])
  master_ips      = lookup(var.master, "fixed_ips", [])
  worker_ips      = lookup(var.worker, "fixed_ips", [])
}
