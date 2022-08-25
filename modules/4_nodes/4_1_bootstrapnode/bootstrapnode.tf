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

#bootstrap
data "ignition_config" "bootstrap" {
  merge {
    source = "http://${var.bastion_ip}:8080/ignition/bootstrap.ign"
  }
  files = [data.ignition_file.b_hostname.rendered]
}

data "ignition_file" "b_hostname" {
  overwrite = true
  mode      = "420" // 0644
  path      = "/etc/hostname"
  content {
    mime    = "text/plain"
    content = <<EOF
bootstrap
EOF
  }
}

resource "openstack_compute_flavor_v2" "bootstrap_scg" {
  count        = var.scg_id == "" || var.bootstrap["count"] == 0 ? 0 : 1
  name         = "${var.bootstrap["instance_type"]}-${random_id.label[0].hex}-scg"
  region       = data.openstack_compute_flavor_v2.bootstrap.region
  ram          = data.openstack_compute_flavor_v2.bootstrap.ram
  vcpus        = data.openstack_compute_flavor_v2.bootstrap.vcpus
  disk         = data.openstack_compute_flavor_v2.bootstrap.disk
  swap         = data.openstack_compute_flavor_v2.bootstrap.swap
  rx_tx_factor = data.openstack_compute_flavor_v2.bootstrap.rx_tx_factor
  is_public    = data.openstack_compute_flavor_v2.bootstrap.is_public
  extra_specs  = merge(data.openstack_compute_flavor_v2.bootstrap.extra_specs, { "powervm:storage_connectivity_group" : var.scg_id })
}

data "openstack_compute_flavor_v2" "bootstrap" {
  name = var.bootstrap["instance_type"]
}

resource "openstack_compute_instance_v2" "bootstrap" {
  depends_on = [var.install_status]

  # Only 1 node is supported
  count             = var.bootstrap["count"] == 0 ? 0 : 1
  name              = "${var.cluster_id}-bootstrap"
  flavor_id         = var.scg_id == "" ? data.openstack_compute_flavor_v2.bootstrap.id : openstack_compute_flavor_v2.bootstrap_scg[0].id
  image_id          = var.bootstrap["image_id"]
  availability_zone = lookup(var.bootstrap, "availability_zone", var.openstack_availability_zone)

  user_data = replace(data.ignition_config.bootstrap.rendered, "\"timeouts\":{}", "\"timeouts\":{\"httpTotal\":500}")

  network {
    port = var.bootstrap_port_id
  }
}
