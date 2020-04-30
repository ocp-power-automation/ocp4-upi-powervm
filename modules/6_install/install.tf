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

resource "null_resource" "check_bootstrap" {
    provisioner "remote-exec" {
        connection {
            host        = var.bootstrap_ip
            user        = "core"
            private_key = var.private_key
            agent       = var.ssh_agent
            timeout     = "15m"
        }
        inline = [
          "whoami",
          "if lsmod|grep -q 'ibmveth'; then UUID=$(sudo nmcli -t c show --active | cut -d \":\" -f 2) ; sudo nmcli conn modify $UUID ethtool.feature-tso off; fi"
        ]
    }
}

resource "null_resource" "check_master" {
    count = length(var.master_ips)
    provisioner "remote-exec" {
        connection {
            host        = var.master_ips[count.index]
            user        = "core"
            private_key = var.private_key
            agent       = var.ssh_agent
            timeout     = "15m"
        }
        inline = [
          "whoami",
          "if lsmod|grep -q 'ibmveth'; then UUID=$(sudo nmcli -t c show --active | cut -d \":\" -f 2) ; sudo nmcli conn modify $UUID ethtool.feature-tso off; fi"
        ]
    }
}

resource "null_resource" "wait_bootstrap" {
    depends_on = [null_resource.check_bootstrap, null_resource.check_master]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi",
            "./openshift-install wait-for bootstrap-complete",
        ]
    }
}

resource "null_resource" "check_worker" {
    depends_on          = [null_resource.wait_bootstrap]
    count               = length(var.worker_ips)
    provisioner "remote-exec" {
        connection {
            host        = var.worker_ips[count.index]
            user        = "core"
            private_key = var.private_key
            agent       = var.ssh_agent
            timeout     = "15m"
        }
        inline = [
          "whoami",
          "if lsmod|grep -q 'ibmveth'; then UUID=$(sudo nmcli -t c show --active | cut -d \":\" -f 2) ; sudo nmcli conn modify $UUID ethtool.feature-tso off; fi"
        ]
    }
}

resource "null_resource" "setup_oc" {
    depends_on = [null_resource.wait_bootstrap]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi",
            "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null core@${var.bootstrap_ip}:/bin/oc ~/openstack-upi",
            "sudo cp ~/openstack-upi/oc /bin/oc",
            "mkdir -p ~/.kube/",
            "cp ~/openstack-upi/auth/kubeconfig ~/.kube/config"
        ]
    }
}

resource "null_resource" "approve_worker_csr" {
    depends_on = [null_resource.setup_oc, null_resource.check_worker]
        connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline = [
            # Approving all CSR requests until worker nodes are Ready...
            "while [ $(oc get nodes | grep worker | grep NotReady | wc -l) != 0 ]; do oc get csr -ojson | jq -r '.items[] | select(.status == {} ) | .metadata.name' | xargs oc adm certificate approve; sleep 30; echo 'Worker not Ready, sleeping for 30s..'; done"
        ]
    }
}

resource "null_resource" "patch_image_registry" {
    depends_on = [null_resource.approve_worker_csr]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "file" {
        content = <<EOF
#!/bin/bash

# The image-registry is not always available immediately after the OCP installer
while [ $(oc get configs.imageregistry.operator.openshift.io/cluster | wc -l) == 0 ]; do sleep 30; done
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"storage":{"emptyDir":{}}, "managementState": "Managed"}}'

EOF
        destination = "/tmp/patch_image_registry.sh"
    }
    provisioner "remote-exec" {
        inline = [
            "chmod +x /tmp/patch_image_registry.sh; bash /tmp/patch_image_registry.sh",
        ]
    }
}

resource "null_resource" "wait_install" {
    depends_on = [null_resource.patch_image_registry]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi",
            "./openshift-install wait-for install-complete",
            "\\cp ~/openstack-upi/auth/kubeconfig ~/.kube/config"
        ]
    }
}
