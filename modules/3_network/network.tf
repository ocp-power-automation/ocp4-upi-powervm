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
    binding {
       vnic_type = var.network_type == "SRIOV" ?  "direct" : "normal"
       profile   = var.network_type == "SRIOV" ?  local.sriov : null
     }
    extra_dhcp_option {
        name  = "domain-search"
        value = var.cluster_domain
    }
}

resource "openstack_networking_port_v2" "master_port" {
    count           = var.master_count
    name            = "${var.cluster_id}-master-port-${count.index}"
    network_id      = data.openstack_networking_network_v2.network.id
    admin_state_up  = "true"
    binding {
       vnic_type = var.network_type == "SRIOV" ?  "direct" : "normal"
       profile   = var.network_type == "SRIOV" ?  local.sriov : null
     }
    extra_dhcp_option {
        name        = "domain-search"
        value       = var.cluster_domain
    }
}

resource "openstack_networking_port_v2" "worker_port" {
    count           = var.worker_count
    name            = "${var.cluster_id}-worker-port-${count.index}"
    network_id      = data.openstack_networking_network_v2.network.id
    admin_state_up  = "true"
    binding {
       vnic_type = var.network_type == "SRIOV" ?  "direct" : "normal"
       profile   = var.network_type == "SRIOV" ?  local.sriov : null
     }
    extra_dhcp_option {
        name  = "domain-search"
        value = var.cluster_domain
    }
}

locals {
    master_mac          = openstack_networking_port_v2.master_port.*.mac_address
    master_ip           = openstack_networking_port_v2.master_port.*.all_fixed_ips
    worker_mac          = openstack_networking_port_v2.worker_port.*.mac_address
    worker_ip           = openstack_networking_port_v2.worker_port.*.all_fixed_ips

    dhcp_config = {
        bastion_ip          = var.bastion_ip
        cluster_subnet      = cidrhost(data.openstack_networking_subnet_v2.subnet.cidr, 0)
        cluster_subnet_mask = cidrnetmask(data.openstack_networking_subnet_v2.subnet.cidr)
        gateway_ip_address  = data.openstack_networking_subnet_v2.subnet.gateway_ip
        cluster_domain_name = var.cluster_domain
        bootstrap_mac       = openstack_networking_port_v2.bootstrap_port.mac_address
        bootstrap_ip        = openstack_networking_port_v2.bootstrap_port.all_fixed_ips[0]
        master_info         = [for ix in range(length(local.master_mac)): {index = ix, ip = local.master_ip[ix][0], mac = local.master_mac[ix]}]
        worker_info         = [for ix in range(length(local.worker_mac)): {index = ix, ip = local.worker_ip[ix][0], mac = local.worker_mac[ix]}]
        cluster_id          = var.cluster_id
    }

   sriov   = <<EOF
   {
       "delete_with_instance": 1,
       "vnic_required_vfs": 1,
       "capacity": 0.02,
       "vlan_type": "allowed"
   }
   EOF  
}

resource "null_resource" "setup_dhcp" {
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        content      = templatefile("${path.module}/dhcp.conf", local.dhcp_config)
        destination = "/tmp/dhcp.conf"
    }
    provisioner "remote-exec" {
        inline = [
            "sudo yum install -y dhcp-server",
            "sudo mkdir -p /etc/dhcp",
            "sudo cp /tmp/dhcp.conf /etc/dhcp/dhcpd.conf",
            "sudo chmod 644 /etc/dhcp/dhcpd.conf",
            "sudo firewall-cmd --add-service=dhcp --permanent",
            "sudo firewall-cmd --reload",
            "sudo systemctl enable --now dhcpd",
            "sudo systemctl restart dhcpd"
        ]
    }
}
