#bootstrap
data "ignition_config" "bootstrap" {
    append {
        source  = var.bootstrap_ign_url
    }
    files       = [
        data.ignition_file.b_hostname.rendered,
    ]
}

data "ignition_file" "b_hostname" {
    filesystem  = "root"
    mode        = "420" // 0644
    path        = "/etc/hostname"
    content {
        content = <<EOF
${var.cluster_id}-bootstrap
EOF
    }
}

resource "openstack_compute_instance_v2" "bootstrap" {
    name        = "${var.cluster_id}-bootstrap"
    flavor_name = var.bootstrap["instance_type"]
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
        element(data.ignition_file.m_hostname.*.rendered, count.index)
    ]
}

data "ignition_file" "m_hostname" {
    count       = var.master["count"]
    filesystem  = "root"
    mode        = "420" // 0644
    path        = "/etc/hostname"
    content {
    content     = <<EOF
${var.cluster_id}-master-${count.index}
EOF
    }
}

resource "openstack_compute_instance_v2" "master" {
    name        = "${var.cluster_id}-master-${count.index}"
    count       = var.master["count"]
    flavor_name = var.master["instance_type"]
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
${var.cluster_id}-worker-${count.index}
EOF
    }
}

data "ignition_config" "worker" {
    count       = var.worker["count"]
    append {
        source  = var.worker_ign_url
    }
    files       = [
        element(data.ignition_file.w_hostname.*.rendered, count.index)
    ]
}

resource "openstack_compute_instance_v2" "worker" {
    name        = "${var.cluster_id}-worker-${count.index}"
    count       = var.worker["count"]
    flavor_name = var.worker["instance_type"]
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
