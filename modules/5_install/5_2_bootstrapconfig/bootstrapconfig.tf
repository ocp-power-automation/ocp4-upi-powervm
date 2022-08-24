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


resource "null_resource" "bootstrap_config" {
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
      "cd ocp4-playbooks && ansible-playbook -i inventory -e @install_vars.yaml playbooks/bootstrap-config.yaml ${var.ansible_extra_options}"
    ]
  }
}
