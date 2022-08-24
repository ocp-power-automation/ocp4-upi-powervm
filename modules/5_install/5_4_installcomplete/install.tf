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

locals {
  wildcard_dns   = ["nip.io", "xip.io", "sslip.io"]
  cluster_domain = contains(local.wildcard_dns, var.cluster_domain) ? "${var.bastion_vip != "" ? var.bastion_vip : var.bastion_ip[0]}.${var.cluster_domain}" : var.cluster_domain

  upgrade_vars = {
    upgrade_version = var.upgrade_version
    upgrade_channel = var.upgrade_channel
    upgrade_image   = var.upgrade_image
    pause_time      = var.upgrade_pause_time
    delay_time      = var.upgrade_delay_time
  }
}



resource "null_resource" "install" {
  triggers = {
    worker_count = length(var.worker_ips)
  }

  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = var.bastion_ip[0]
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
    bastion_host = var.jump_host
  }

  provisioner "remote-exec" {
    inline = [
      "echo 'Running ocp install playbook...'",
      "cd ocp4-playbooks && ansible-playbook -i inventory -e @install_vars.yaml playbooks/install-complete.yaml ${var.ansible_extra_options}"
    ]
  }
}

resource "null_resource" "upgrade" {
  depends_on = [null_resource.install]
  count      = (var.upgrade_version != "" || var.upgrade_image != "") != "" ? 1 : 0

  connection {
    type         = "ssh"
    user         = var.rhel_username
    host         = var.bastion_ip[0]
    private_key  = var.private_key
    agent        = var.ssh_agent
    timeout      = "${var.connection_timeout}m"
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

