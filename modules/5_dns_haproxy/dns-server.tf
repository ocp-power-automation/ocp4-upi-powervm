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
    script_cfg = {
        bastion_ip = var.bastion_ip
        sourcedir = "$HOME/setup-files/dns-setup"
    }
}

# Setup BIND.
resource "null_resource" "do_setup" {
    count       = var.dns_enabled == "true" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline  = [
            "rm -rf ${local.script_cfg.sourcedir}",
            "mkdir -p ${local.script_cfg.sourcedir}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/dns-enable.sh", local.script_cfg)
        destination = "${local.script_cfg.sourcedir}/dns-enable.sh"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/dns-disable.sh", local.script_cfg)
        destination = "${local.script_cfg.sourcedir}/dns-disable.sh"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/named.conf", local.named_cfg)
        destination = "${local.script_cfg.sourcedir}/named.conf"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/cluster-zone.db", local.named_cfg)
        destination = "${local.script_cfg.sourcedir}/cluster-zone.db"
    }
    provisioner "remote-exec" {
        inline  = [
            "chmod +x ${local.script_cfg.sourcedir}/dns-enable.sh",
            "${local.script_cfg.sourcedir}/dns-enable.sh",
        ]
    }
    provisioner "remote-exec" {
        when    = destroy
        on_failure = continue
        inline  = [
            "chmod +x ${local.script_cfg.sourcedir}/dns-disable.sh",
            "${local.script_cfg.sourcedir}/dns-disable.sh || true",
            "rmdir --ignore-fail-on-non-empty ${local.script_cfg.sourcedir}"
        ]
    }
}
