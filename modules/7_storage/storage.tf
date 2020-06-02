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
    nfs_storage_config = {
        server_ip   = var.bastion_ip
        server_path = "/export"
    }
    storageclass_config = {
        storageclass_name   = var.storageclass_name
    }
}

resource "null_resource" "configure_nfs_storage" {
    depends_on  = [var.install_status]
    count       = var.storage_type == "nfs" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/deployment.yaml", local.nfs_storage_config)
        destination = "/tmp/deployment.yaml"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/class.yaml", local.storageclass_config)
        destination = "/tmp/class.yaml"
    }
    provisioner "file" {
        source      = "${path.module}/templates/rbac.yaml"
        destination = "/tmp/rbac.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "oc create -f /tmp/rbac.yaml",
            "oc adm policy add-scc-to-user hostmount-anyuid system:serviceaccount:default:nfs-client-provisioner",
            "oc create -f /tmp/class.yaml",
            "oc create -f /tmp/deployment.yaml"
        ]
    }
    provisioner "remote-exec" {
        when        = destroy
        on_failure  = continue
        inline = [
            "oc delete -f /tmp/deployment.yaml",
            "oc delete -f /tmp/class.yaml",
            "oc delete -f /tmp/rbac.yaml",
            
        ]
    }
}


resource "null_resource" "patch_image_registry" {
    depends_on = [null_resource.configure_nfs_storage]
    count       = var.storage_type == "nfs" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        source      = "${path.module}/templates/pvc-nfs.yaml"
        destination = "/tmp/pvc-nfs.yaml"
    }

    provisioner "remote-exec" {
        inline = [
            "oc create -f /tmp/pvc-nfs.yaml -n openshift-image-registry",
        ]
    }


    provisioner "file" {
        content = <<EOF
#!/bin/bash

# The image-registry is not always available immediately after the OCP installer
while [ $(oc get configs.imageregistry.operator.openshift.io/cluster | wc -l) == 0 ]; do sleep 30; done
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"storage":{"pvc":{"claim":"registrypvc"}}, "managementState": "Managed"}}'

EOF
        destination = "/tmp/patch_image_registry.sh"
    }
    provisioner "remote-exec" {
        inline = [
            "chmod +x /tmp/patch_image_registry.sh; bash /tmp/patch_image_registry.sh",
        ]
    }
}

