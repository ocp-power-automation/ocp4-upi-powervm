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

    local_registry  = {
        enable_local_registry   = var.enable_local_registry
        registry_image          = var.local_registry_image
        ocp_release_repo        = "ocp4/openshift4"
        ocp_release_tag         = var.ocp_release_tag
    }

    helpernode_vars = {
        cluster_domain  = local.cluster_domain
        cluster_id      = var.cluster_id
        bastion_ip      = var.bastion_vip != "" ? var.bastion_vip : var.bastion_ip[0]
        forwarders      = var.dns_forwarders
        gateway_ip      = var.gateway_ip
        netmask         = cidrnetmask(var.cidr)
        broadcast       = cidrhost(var.cidr,-1)
        ipid            = cidrhost(var.cidr, 0)
        pool            = var.allocation_pools[0]
        chrony_config           = var.chrony_config
        chrony_config_servers   = var.chrony_config_servers

        bootstrap_info  = {
            ip = var.bootstrap_port_ip,
            mac = var.bootstrap_mac,
            name = "bootstrap"
        }
        master_info     = [ for ix in range(length(var.master_port_ips)) :
            {
                ip = var.master_port_ips[ix],
                mac = var.master_macs[ix],
                name = "master-${ix}"
            }
        ]
        worker_info     = [ for ix in range(length(var.worker_port_ips)) :
            {
                ip = var.worker_port_ips[ix],
                mac = var.worker_macs[ix],
                name = "worker-${ix}"
            }
        ]

        local_registry           = local.local_registry
        client_tarball           = var.openshift_client_tarball
        install_tarball          = var.openshift_install_tarball
    }
    helpernode_inventory = {
        bastion_ip  = var.bastion_ip
    }
}

resource "null_resource" "config" {

    triggers = {
        bootstrap_count = var.bootstrap_port_ip == "" ? 0 : 1
        worker_count    = length(var.worker_port_ips)
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
            "mkdir -p .openshift",
            "rm -rf ocp4-helpernode",
            "echo 'Cloning into ocp4-helpernode...'",
            "git clone ${var.helpernode_repo} --quiet",
            "cd ocp4-helpernode && git checkout ${var.helpernode_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/helpernode_inventory", local.helpernode_inventory)
        destination = "$HOME/ocp4-helpernode/inventory"
    }
    provisioner "file" {
        content     = var.pull_secret
        destination = "$HOME/.openshift/pull-secret"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/helpernode_vars.yaml", local.helpernode_vars)
        destination = "$HOME/ocp4-helpernode/helpernode_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp4-helpernode playbook...'",
            "cd ocp4-helpernode && ansible-playbook  -i inventory -e @helpernode_vars.yaml tasks/main.yml ${var.ansible_extra_options}"
        ]
    }
}
