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
    cluster_domain  = var.cluster_domain == "nip.io" || var.cluster_domain == "xip.io" || var.cluster_domain == "sslip.io" ? "${var.bastion_ip}.${var.cluster_domain}" : var.cluster_domain

    ocp_release_repo    = "ocp4/openshift4"

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

    local_registry_ocp_image = "registry.${var.cluster_id}.${local.cluster_domain}:5000/${local.ocp_release_repo}:${var.ocp_release_tag}"

    install_vars = {
        cluster_id              = var.cluster_id
        cluster_domain          = local.cluster_domain
        pull_secret             = var.pull_secret
        public_ssh_key          = var.public_key
        storage_type            = var.storage_type
        log_level               = var.log_level
        release_image_override  = var.enable_local_registry ? local.local_registry_ocp_image : var.release_image_override
        enable_local_registry   = var.enable_local_registry
        node_connection_timeout = 60 * var.connection_timeout
        rhcos_kernel_options    = var.rhcos_kernel_options
        sysctl_tuned_options    = var.sysctl_tuned_options
        sysctl_options          = var.sysctl_options
        match_array             = indent(2,var.match_array)
        setup_squid_proxy       = var.setup_squid_proxy
        squid_source_range      = var.cidr
        proxy_url               = local.proxy.server == "" ? "" : "http://${local.proxy.user_pass}${local.proxy.server}:${local.proxy.port}"
        no_proxy                = var.cidr
        chrony_config           = var.chrony_config
        chrony_config_servers   = var.chrony_config_servers
        chrony_allow_range      = var.cidr
    }

    upgrade_vars = {
        upgrade_version = var.upgrade_version
        upgrade_channel = var.upgrade_channel
        pause_time      = var.upgrade_pause_time
        delay_time      = var.upgrade_delay_time
    }
}

resource "null_resource" "install" {
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
            "git clone ${var.install_playbook_repo} --quiet",
            "cd ocp4-playbooks && git checkout ${var.install_playbook_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/inventory", local.inventory)
        destination = "$HOME/ocp4-playbooks/inventory"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/install_vars.yaml", local.install_vars)
        destination = "$HOME/ocp4-playbooks/install_vars.yaml"
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
    count      = var.upgrade_version != "" ? 1 : 0

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
        destination = "$HOME/ocp4-playbooks/upgrade_vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp upgrade playbook...'",
            "cd ocp4-playbooks && ansible-playbook -i inventory -e @upgrade_vars.yaml playbooks/upgrade.yaml ${var.ansible_extra_options}"
        ]
    }
}

