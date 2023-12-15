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

resource "random_id" "label" {
  count       = var.scg_id == "" ? 0 : 1
  byte_length = "2"
}


#worker
data "ignition_config" "worker" {
  count = var.worker["count"]
  merge {
    source = "http://${var.bastion_ip}:8080/ignition/worker.ign"
  }
  files = [data.ignition_file.w_hostname[count.index].rendered]
}

data "ignition_file" "w_hostname" {
  count     = var.worker["count"]
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"

  content {
    mime    = "text/plain"
    content = <<EOF
worker-${count.index}
EOF
  }
}

resource "openstack_compute_flavor_v2" "worker_scg" {
  count        = var.scg_id == "" || var.worker["count"] == 0 ? 0 : 1
  name         = "${var.worker["instance_type"]}-${random_id.label[0].hex}-scg"
  region       = data.openstack_compute_flavor_v2.worker.region
  ram          = data.openstack_compute_flavor_v2.worker.ram
  vcpus        = data.openstack_compute_flavor_v2.worker.vcpus
  disk         = data.openstack_compute_flavor_v2.worker.disk
  swap         = data.openstack_compute_flavor_v2.worker.swap
  rx_tx_factor = data.openstack_compute_flavor_v2.worker.rx_tx_factor
  is_public    = var.scg_flavor_is_public
  extra_specs  = merge(data.openstack_compute_flavor_v2.worker.extra_specs, { "powervm:storage_connectivity_group" : var.scg_id })
}

data "openstack_compute_flavor_v2" "worker" {
  name = var.worker["instance_type"]
}

resource "openstack_compute_instance_v2" "worker" {
  depends_on = [var.installconfig_status, var.bootstrapcomplete_status]
  count      = var.worker["count"]

  name              = "${var.cluster_id}-worker-${count.index}"
  flavor_id         = var.scg_id == "" ? data.openstack_compute_flavor_v2.worker.id : openstack_compute_flavor_v2.worker_scg[0].id
  image_id          = var.worker["image_id"]
  availability_zone = lookup(var.worker, "availability_zone", var.openstack_availability_zone)

  user_data = data.ignition_config.worker[count.index].rendered

  network {
    port = var.worker_port_ids[count.index]
  }
}

locals {
  worker = {
    volume_count = lookup(var.worker, "data_volume_count", 0),
    volume_size  = lookup(var.worker, "data_volume_size", 0)
  }
}

resource "openstack_blockstorage_volume_v3" "worker" {
  depends_on = [openstack_compute_instance_v2.worker]
  count      = local.worker.volume_count * var.worker["count"]
  name       = "${var.cluster_id}-worker-${count.index}-volume"
  size       = local.worker.volume_size
}

resource "openstack_compute_volume_attach_v2" "worker" {
  count       = local.worker.volume_count * var.worker["count"]
  instance_id = openstack_compute_instance_v2.worker.*.id[floor(count.index / local.worker.volume_count)]
  volume_id   = openstack_blockstorage_volume_v3.worker.*.id[count.index]
}

resource "null_resource" "remove_worker" {
  count      = var.worker["count"]
  depends_on = [openstack_compute_instance_v2.worker]
  triggers = {
    bastion_ip         = var.pub_bastion_ip == "" ? var.bastion_ip : var.pub_bastion_ip
    rhel_username      = var.rhel_username
    private_key        = var.private_key
    ssh_agent          = var.ssh_agent
    connection_timeout = var.connection_timeout
    jump_host          = var.jump_host
  }

  provisioner "remote-exec" {
    connection {
      type         = "ssh"
      user         = self.triggers.rhel_username
      host         = self.triggers.bastion_ip
      private_key  = self.triggers.private_key
      agent        = self.triggers.ssh_agent
      timeout      = "${self.triggers.connection_timeout}m"
      bastion_host = self.triggers.jump_host
    }
    when       = destroy
    on_failure = continue
    inline = [<<EOF
oc adm cordon worker-${count.index}
oc adm drain worker-${count.index} --force --delete-local-data --ignore-daemonsets --timeout=180s
oc delete node worker-${count.index}
EOF
    ]
  }
}
