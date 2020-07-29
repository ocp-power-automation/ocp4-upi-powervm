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
    local_registry  = {
        enable_local_registry   = var.enable_local_registry
        registry_image          = var.local_registry_image
        ocp_release_repo        = "ocp4/openshift4"
        ocp_release_tag         = var.ocp_release_tag
    }

    helpernode_vars = {
        cluster_domain  = var.cluster_domain
        cluster_id      = var.cluster_id
        bastion_ip      = var.bastion_ip
        forwarders      = var.dns_forwarders
        gateway_ip      = var.gateway_ip
        netmask         = cidrnetmask(var.cidr)
        broadcast       = cidrhost(var.cidr,-1)
        ipid            = cidrhost(var.cidr, 0)
        pool            = var.allocation_pools[0]

        bootstrap_info  = {
            ip = var.bootstrap_ip,
            mac = var.bootstrap_mac,
            name = "bootstrap.${var.cluster_id}.${var.cluster_domain}"
        }
        master_info     = [ for ix in range(length(var.master_ips)) :
            {
                ip = var.master_ips[ix],
                mac = var.master_macs[ix],
                name = "master-${ix}.${var.cluster_id}.${var.cluster_domain}"
            }
        ]
        worker_info     = [ for ix in range(length(var.worker_ips)) :
            {
                ip = var.worker_ips[ix],
                mac = var.worker_macs[ix],
                name = "worker-${ix}.${var.cluster_id}.${var.cluster_domain}"
            }
        ]

        local_registry           = local.local_registry
        client_tarball           = var.openshift_client_tarball
        install_tarball          = var.openshift_install_tarball
    }

    inventory = {
        bastion_ip      = var.bastion_ip
        bootstrap_ip    = var.bootstrap_ip
        master_ips      = var.master_ips
        worker_ips      = var.worker_ips
    }

    proxy = {
        server      = lookup(var.proxy, "server", ""),
        port        = lookup(var.proxy, "port", "3128"),
        user_pass   = lookup(var.proxy, "user", "") == "" ? "" : "${lookup(var.proxy, "user", "")}:${lookup(var.proxy, "password", "")}@"
    }

    local_registry_ocp_image = "registry.${var.cluster_id}.${var.cluster_domain}:5000/${local.local_registry.ocp_release_repo}:${var.ocp_release_tag}"

    install_vars = {
        cluster_id              = var.cluster_id
        cluster_domain          = var.cluster_domain
        pull_secret             = var.pull_secret
        public_ssh_key          = var.public_key
        storage_type            = var.storage_type
        log_level               = var.log_level
        release_image_override  = var.enable_local_registry ? "${local.local_registry_ocp_image}" : var.release_image_override
        enable_local_registry   = var.enable_local_registry
        node_connection_timeout = "${60 * var.connection_timeout}"
        rhcos_kernel_options    = var.rhcos_kernel_options
        sysctl_tuned_options    = var.sysctl_tuned_options
        sysctl_options          = var.sysctl_options
        chrony_config           = var.chrony_config
        chrony_config_servers   = var.chrony_config_servers
        match_array             = indent(2,var.match_array)
        proxy_url               = local.proxy.server == "" ? "" : "http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}"
        no_proxy                = var.cidr
    }

    upgrade_vars = {
        upgrade_image   = var.upgrade_image
        pause_time      = var.upgrade_pause_time
        delay_time      = var.upgrade_delay_time
    }
}

resource "null_resource" "config" {
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "${var.connection_timeout}m"
        bastion_host = var.jump_host
    }

    provisioner "remote-exec" {
        inline = [
            "mkdir -p .openshift",
            "rm -rf ocp4-helpernode",
            "echo 'Cloning into ocp4-helpernode...'",
            "git clone https://github.com/RedHatOfficial/ocp4-helpernode --quiet",
            "cd ocp4-helpernode && git checkout ${var.helpernode_tag}"
        ]
    }
    provisioner "file" {
        source      = "data/pull-secret.txt"
        destination = "~/.openshift/pull-secret"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/helpernode_vars.yaml", local.helpernode_vars)
        destination = "~/ocp4-helpernode/helpernode_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp4-helpernode playbook...'",
            "cd ocp4-helpernode && ansible-playbook -e @helpernode_vars.yaml tasks/main.yml ${var.ansible_extra_options}"
        ]
    }
}

resource "null_resource" "install" {
    depends_on = [null_resource.config]

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "${var.connection_timeout}m"
        bastion_host = var.jump_host
    }

    provisioner "remote-exec" {
        inline = [
            "rm -rf ocp4-playbooks",
            "echo 'Cloning into ocp4-playbooks...'",
            "git clone https://github.com/ocp-power-automation/ocp4-playbooks --quiet",
            "cd ocp4-playbooks && git checkout ${var.install_playbook_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/inventory", local.inventory)
        destination = "~/ocp4-playbooks/inventory"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/install_vars.yaml", local.install_vars)
        destination = "~/ocp4-playbooks/install_vars.yaml"
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
    count      = var.upgrade_image != "" ? 1 : 0

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "${var.connection_timeout}m"
        bastion_host = var.jump_host
    }

    provisioner "file" {
        content     = templatefile("${path.module}/templates/upgrade_vars.yaml", local.upgrade_vars)
        destination = "~/ocp4-playbooks/upgrade_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp upgrade playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @upgrade_vars.yaml playbooks/upgrade.yaml ${var.ansible_extra_options}"
        ]
    }
}

