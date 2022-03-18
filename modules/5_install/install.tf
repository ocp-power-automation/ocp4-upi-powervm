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

locals {
    wildcard_dns = ["nip.io", "xip.io", "sslip.io"]
    cluster_domain = contains(local.wildcard_dns, var.cluster_domain) ? "${var.bastion_vip != "" ? var.bastion_vip : var.bastion_ip[0]}.${var.cluster_domain}" : var.cluster_domain

    ocp_release_repo    = "ocp4/openshift4"

    bastion_count = lookup(var.bastion, "count", 1)

    install_inventory = {
        rhel_username   = var.rhel_username
        bastion_hosts   = [for ix in range(length(var.bastion_ip)) : "${var.cluster_id}-bastion-${ix}"]
        bootstrap_host  = var.bootstrap_ip == "" ? "" : "bootstrap"
        master_hosts    = [for ix in range(length(var.master_ips)) : "master-${ix}"]
        worker_hosts    = [for ix in range(length(var.worker_ips)) : "worker-${ix}"]
    }

    proxy = {
        server      = lookup(var.proxy, "server", ""),
        port        = lookup(var.proxy, "port", "3128"),
        user_pass   = lookup(var.proxy, "user", "") == "" ? "" : "${lookup(var.proxy, "user", "")}:${lookup(var.proxy, "password", "")}@"
    }

    local_registry_ocp_image = "registry.${var.cluster_id}.${local.cluster_domain}:5000/${local.ocp_release_repo}:${var.ocp_release_tag}"

    install_vars = {
        bastion_vip                = var.bastion_vip
        cluster_id                 = var.cluster_id
        cluster_domain             = local.cluster_domain
        pull_secret                = var.pull_secret
        public_ssh_key             = var.public_key
        storage_type               = var.storage_type
        log_level                  = var.log_level
        release_image_override     = var.enable_local_registry ? local.local_registry_ocp_image : var.release_image_override
        enable_local_registry      = var.enable_local_registry
        node_connection_timeout    = 60 * var.connection_timeout
        rhcos_pre_kernel_options   = var.rhcos_pre_kernel_options
        rhcos_kernel_options       = var.rhcos_kernel_options
        sysctl_tuned_options       = var.sysctl_tuned_options
        sysctl_options             = var.sysctl_options
        match_array                = indent(2,var.match_array)
        setup_squid_proxy          = var.setup_squid_proxy
        squid_source_range         = var.cidr
        proxy_url                  = local.proxy.server == "" ? "" : "http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}"
        no_proxy                   = var.cidr
        chrony_config              = var.chrony_config
        chrony_config_servers      = var.chrony_config_servers
        chrony_allow_range         = var.cidr
        cni_network_provider       = var.cni_network_provider
        cluster_network_cidr       = var.cluster_network_cidr
        cluster_network_hostprefix = var.cluster_network_hostprefix
        service_network            = var.service_network
        # Set CNI network MTU to MTU - 100 for OVNKubernetes and MTU - 50 for OpenShiftSDN(default).
        # Add new conditions here when we have more network providers
        cni_network_mtu = var.cni_network_provider == "OVNKubernetes" ? var.private_network_mtu - 100 : var.private_network_mtu - 50
    }

    upgrade_vars = {
        upgrade_version = var.upgrade_version
        upgrade_channel = var.upgrade_channel
        upgrade_image   = var.upgrade_image
        pause_time      = var.upgrade_pause_time
        delay_time      = var.upgrade_delay_time
    }
}

resource "null_resource" "pre_install" {
  count      = local.bastion_count

  connection {
    type        = "ssh"
    user        = var.rhel_username
    host        = var.bastion_ip[count.index]
    private_key = var.private_key
    agent       = var.ssh_agent
    timeout     = "${var.connection_timeout}m"
    bastion_host = var.jump_host
  }

  # DHCP config for setting MTU; Since helpernode DHCP template does not support MTU setting
  provisioner "remote-exec" {
    inline = [
      # Set specified mtu for private interface.
      "sudo ip link set dev $(ip r | grep \"${var.cidr} dev\" | awk '{print $3}') mtu ${var.private_network_mtu}",
      "echo MTU=${var.private_network_mtu} | sudo tee -a /etc/sysconfig/network-scripts/ifcfg-$(ip r | grep ${var.cidr} | awk '{print $3}')",
      # DHCP config for setting MTU;
      "sed -i.mtubak '/option routers/i option interface-mtu ${var.private_network_mtu};' /etc/dhcp/dhcpd.conf",
      "sudo systemctl restart dhcpd.service"
    ]
  }
}

resource "null_resource" "install" {
    depends_on = [null_resource.pre_install]

    triggers = {
        worker_count    = length(var.worker_ips)
    }

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip[0]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "${var.connection_timeout}m"
        bastion_host = var.jump_host
    }

    provisioner "remote-exec" {
        inline = [
            "rm -rf ocp4-playbooks",
            "echo 'Cloning into ocp4-playbooks...'",
            "git clone ${var.install_playbook_repo} --quiet",
            "cd ocp4-playbooks && git checkout ${var.install_playbook_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/install_inventory", local.install_inventory)
        destination = "ocp4-playbooks/inventory"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/install_vars.yaml", local.install_vars)
        destination = "ocp4-playbooks/install_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp install playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @install_vars.yaml playbooks/install.yaml ${var.ansible_extra_options}"
        ]
    }
}

resource "null_resource" "upgrade" {
    depends_on = [null_resource.install]
    count      = (var.upgrade_version != "" || var.upgrade_image != "" ) != "" ? 1 : 0

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip[0]
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "${var.connection_timeout}m"
        bastion_host = var.jump_host
    }

    provisioner "file" {
        content     = templatefile("${path.module}/templates/upgrade_vars.yaml", local.upgrade_vars)
        destination = "ocp4-playbooks/upgrade_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp upgrade playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @upgrade_vars.yaml playbooks/upgrade.yaml ${var.ansible_extra_options}"
        ]
    }
}

