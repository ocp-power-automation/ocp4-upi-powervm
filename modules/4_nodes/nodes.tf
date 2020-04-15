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

resource "random_id" "label" {
    count       = var.scg_id == "" ? 0 : 3
    byte_length = "2"
}

#common
data "ignition_file" "pmtu" {
    filesystem  = "root"
    mode        = "420"
    path        = "/etc/sysctl.d/88-sysctl.conf"
    content {
        content = <<EOF
net.ipv4.ip_no_pmtu_disc = 1
EOF
    }
}


#bootstrap
data "ignition_config" "bootstrap" {
    append {
        source  = var.bootstrap_ign_url
    }
    files       = [
        data.ignition_file.b_hostname.rendered,
        data.ignition_file.pmtu.rendered
    ]
}

data "ignition_file" "b_hostname" {
    filesystem  = "root"
    mode        = "420" // 0644
    path        = "/etc/hostname"
    content {
        content = <<EOF
bootstrap.${var.cluster_id}.${var.cluster_domain}
EOF
    }
}

resource "openstack_compute_flavor_v2" "bootstrap_scg" {
    count       = var.scg_id == "" || var.bootstrap["count"] == 0 ? 0 : 1
    name        = "${var.bootstrap["instance_type"]}-${random_id.label[0].hex}-scg"
    region      = data.openstack_compute_flavor_v2.bootstrap.region
    ram         = data.openstack_compute_flavor_v2.bootstrap.ram
    vcpus       = data.openstack_compute_flavor_v2.bootstrap.vcpus
    disk        = data.openstack_compute_flavor_v2.bootstrap.disk
    swap        = data.openstack_compute_flavor_v2.bootstrap.swap
    rx_tx_factor    = data.openstack_compute_flavor_v2.bootstrap.rx_tx_factor
    is_public   = data.openstack_compute_flavor_v2.bootstrap.is_public
    extra_specs = merge(data.openstack_compute_flavor_v2.bootstrap.extra_specs, {"powervm:storage_connectivity_group": var.scg_id})
}

data "openstack_compute_flavor_v2" "bootstrap" {
    name = var.bootstrap["instance_type"]
}

resource "openstack_compute_instance_v2" "bootstrap" {
    # Only 1 node is supported
    count       = var.bootstrap["count"] == 0 ? 0 : 1
    name        = "${var.cluster_id}-bootstrap"
    flavor_id   = var.scg_id == "" ? data.openstack_compute_flavor_v2.bootstrap.id : openstack_compute_flavor_v2.bootstrap_scg[0].id
    image_id    = var.bootstrap["image_id"]
    availability_zone   = var.openstack_availability_zone

    user_data   = data.ignition_config.bootstrap.rendered

    network {
        port    = var.bootstrap_port_id
    }
}


#master
data "ignition_config" "master" {
    count       = var.master["count"]
    append {
        source  = var.master_ign_url
    }
    files       = [
        element(data.ignition_file.m_hostname.*.rendered, count.index),
        data.ignition_file.pmtu.rendered
    ]
}

data "ignition_file" "m_hostname" {
    count       = var.master["count"]
    filesystem  = "root"
    mode        = "420" // 0644
    path        = "/etc/hostname"
    content {
    content     = <<EOF
master-${count.index}.${var.cluster_id}.${var.cluster_domain}
EOF
    }
}

resource "openstack_compute_flavor_v2" "master_scg" {
    count       = var.scg_id == "" || var.master["count"] == 0 ? 0 : 1
    name        = "${var.master["instance_type"]}-${random_id.label[1].hex}-scg"
    region      = data.openstack_compute_flavor_v2.master.region
    ram         = data.openstack_compute_flavor_v2.master.ram
    vcpus       = data.openstack_compute_flavor_v2.master.vcpus
    disk        = data.openstack_compute_flavor_v2.master.disk
    swap        = data.openstack_compute_flavor_v2.master.swap
    rx_tx_factor    = data.openstack_compute_flavor_v2.master.rx_tx_factor
    is_public   = data.openstack_compute_flavor_v2.master.is_public
    extra_specs = merge(data.openstack_compute_flavor_v2.master.extra_specs, {"powervm:storage_connectivity_group": var.scg_id})
}

data "openstack_compute_flavor_v2" "master" {
    name = var.master["instance_type"]
}

resource "openstack_compute_instance_v2" "master" {
    name        = "${var.cluster_id}-master-${count.index}"
    count       = var.master["count"]
    flavor_id   = var.scg_id == "" ? data.openstack_compute_flavor_v2.master.id : openstack_compute_flavor_v2.master_scg[0].id
    image_id    = var.master["image_id"]
    availability_zone   = var.openstack_availability_zone

    user_data   = element(
        data.ignition_config.master.*.rendered,
        count.index,
    )

    network {
        port    = var.master_port_ids[count.index]
    }
}


#worker
data "ignition_file" "w_hostname" {
    count       = var.worker["count"]
    filesystem  = "root"
    mode        = "420" // 0644
    path        = "/etc/hostname"

    content {
    content     = <<EOF
worker-${count.index}.${var.cluster_id}.${var.cluster_domain}
EOF
    }
}

data "ignition_config" "worker" {
    count       = var.worker["count"]
    append {
        source  = var.worker_ign_url
    }
    files       = [
        element(data.ignition_file.w_hostname.*.rendered, count.index),
        data.ignition_file.pmtu.rendered
    ]
}

resource "openstack_compute_flavor_v2" "worker_scg" {
    count       = var.scg_id == "" || var.worker["count"] == 0 ? 0 : 1
    name        = "${var.worker["instance_type"]}-${random_id.label[2].hex}-scg"
    region      = data.openstack_compute_flavor_v2.worker.region
    ram         = data.openstack_compute_flavor_v2.worker.ram
    vcpus       = data.openstack_compute_flavor_v2.worker.vcpus
    disk        = data.openstack_compute_flavor_v2.worker.disk
    swap        = data.openstack_compute_flavor_v2.worker.swap
    rx_tx_factor    = data.openstack_compute_flavor_v2.worker.rx_tx_factor
    is_public   = data.openstack_compute_flavor_v2.worker.is_public
    extra_specs = merge(data.openstack_compute_flavor_v2.worker.extra_specs, {"powervm:storage_connectivity_group": var.scg_id})
}

data "openstack_compute_flavor_v2" "worker" {
    name = var.worker["instance_type"]
}

resource "openstack_compute_instance_v2" "worker" {
    name        = "${var.cluster_id}-worker-${count.index}"
    count       = var.worker["count"]
    flavor_id   = var.scg_id == "" ? data.openstack_compute_flavor_v2.worker.id : openstack_compute_flavor_v2.worker_scg[0].id
    image_id    = var.worker["image_id"]
    availability_zone   = var.openstack_availability_zone

    user_data = element(
        data.ignition_config.worker.*.rendered,
        count.index,
    )

    network {
        port = var.worker_port_ids[count.index]
    }
}
