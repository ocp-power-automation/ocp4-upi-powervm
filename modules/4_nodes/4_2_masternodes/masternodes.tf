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

#master
data "ignition_systemd_unit" "ramdisk" {
  count   = var.mount_etcd_ramdisk ? 1 : 0
  name    = "var-lib-etcd.mount"
  content = "[Unit]\nDescription=Mount etcd as a ramdisk\nBefore=local-fs.target\n[Mount]\n What=none\nWhere=/var/lib/etcd\nType=tmpfs\nOptions=size=2G\n[Install]\nWantedBy=local-fs.target"
}

data "ignition_config" "master" {
  count = var.master["count"]
  merge {
    source = "http://${var.bastion_ip}:8080/ignition/master.ign"
  }
  files   = [data.ignition_file.m_hostname[count.index].rendered]
  systemd = data.ignition_systemd_unit.ramdisk.*.rendered
}

data "ignition_file" "m_hostname" {
  count     = var.master["count"]
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"
  content {
    mime    = "text/plain"
    content = <<EOF
master-${count.index}
EOF
  }
}

resource "openstack_compute_flavor_v2" "master_scg" {
  count        = var.scg_id == "" || var.master["count"] == 0 ? 0 : 1
  name         = "${var.master["instance_type"]}-${random_id.label[0].hex}-scg"
  region       = data.openstack_compute_flavor_v2.master.region
  ram          = data.openstack_compute_flavor_v2.master.ram
  vcpus        = data.openstack_compute_flavor_v2.master.vcpus
  disk         = data.openstack_compute_flavor_v2.master.disk
  swap         = data.openstack_compute_flavor_v2.master.swap
  rx_tx_factor = data.openstack_compute_flavor_v2.master.rx_tx_factor
  is_public    = data.openstack_compute_flavor_v2.master.is_public
  extra_specs  = merge(data.openstack_compute_flavor_v2.master.extra_specs, { "powervm:storage_connectivity_group" : var.scg_id })
}

data "openstack_compute_flavor_v2" "master" {
  name = var.master["instance_type"]
}

resource "openstack_compute_instance_v2" "master" {
  depends_on = [var.install_status]
  count      = var.master["count"]

  name              = "${var.cluster_id}-master-${count.index}"
  flavor_id         = var.scg_id == "" ? data.openstack_compute_flavor_v2.master.id : openstack_compute_flavor_v2.master_scg[0].id
  image_id          = var.master["image_id"]
  availability_zone = lookup(var.master, "availability_zone", var.openstack_availability_zone)

  user_data = replace(data.ignition_config.master[count.index].rendered, "\"timeouts\":{}", "\"timeouts\":{\"httpTotal\":500}")

  network {
    port = var.master_port_ids[count.index]
  }
}

locals {
  master = {
    volume_count = lookup(var.master, "data_volume_count", 0),
    volume_size  = lookup(var.master, "data_volume_size", 0)
  }
}

resource "openstack_blockstorage_volume_v2" "master" {
  depends_on = [openstack_compute_instance_v2.master]
  count      = local.master.volume_count * var.master["count"]
  name       = "${var.cluster_id}-master-${count.index}-volume"
  size       = local.master.volume_size
}

resource "openstack_compute_volume_attach_v2" "master" {
  count       = local.master.volume_count * var.master["count"]
  instance_id = openstack_compute_instance_v2.master.*.id[floor(count.index / local.master.volume_count)]
  volume_id   = openstack_blockstorage_volume_v2.master.*.id[count.index]
}
