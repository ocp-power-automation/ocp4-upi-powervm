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

resource "openstack_blockstorage_volume_v2" "storage_volume" {
    depends_on  = [var.install_status]
    name        = "${var.cluster_id}-${var.storage_type}-storage-vol"
    size        = var.volume_size
    volume_type = var.volume_storage_template
    count       = var.storage_type == "nfs" ? 1 : 0
}

resource "openstack_compute_volume_attach_v2" "storage_v_attach" {
    volume_id   = openstack_blockstorage_volume_v2.storage_volume[count.index].id
    instance_id = var.bastion_id
    count       = var.storage_type == "nfs" ? 1 : 0
}

resource "null_resource" "setup_nfs_server" {
    depends_on  = [openstack_compute_volume_attach_v2.storage_v_attach]
    count       = var.storage_type == "nfs" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.jump_host
    }
    provisioner "remote-exec" {
        inline = [
            "sudo yum install -y nfs-utils",
            "sudo systemctl enable --now rpcbind",
            "sudo systemctl enable --now nfs-server",
            "sudo systemctl start rpcbind",
            "sudo systemctl start nfs-server",
            "sudo firewall-cmd --permanent --zone=public --add-service=nfs",
            "sudo firewall-cmd --permanent --zone=public --add-service=rpc-bind",
            "sudo firewall-cmd --permanent --zone=public --add-service=mountd",
            "sudo firewall-cmd --reload"
        ]
    }
}

locals {
    disk_config = {
        volume_size = var.volume_size
        disk_name   = "disk/pv-storage-disk"
    }
}

resource "null_resource" "setup_nfs_disk" {
    depends_on  = [null_resource.setup_nfs_server]
    count       = var.storage_type == "nfs" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.jump_host
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/create_disk_link.sh", local.disk_config)
        destination = "/tmp/create_disk_link.sh"
    }
    provisioner "remote-exec" {
        inline = [
            "sudo chmod +x /tmp/create_disk_link.sh",
            "/tmp/create_disk_link.sh",
            "sudo mkfs.ext4 -F /dev/${local.disk_config.disk_name}",
            "rm -rf mkdir /var/nfsshare && mkdir /var/nfsshare && chmod -R 755 /var/nfsshare",
            "sudo mount /dev/${local.disk_config.disk_name} /var/nfsshare",
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo sed -i '/^\\/var\\/nfsshare /d' /etc/exports",
            "echo '/var/nfsshare *(rw,sync,no_root_squash)' | sudo tee -a /etc/exports",
            "sudo exportfs -rav",
            "sudo systemctl restart nfs-server"
        ]
    }
}

locals {
    nfs_storage_config = {
        server_ip   = var.bastion_ip
        server_path = "/var/nfsshare"
    }
    storageclass_config = {
        storageclass_name   = var.storageclass_name
    }
    
}

resource "null_resource" "configure_nfs_storage" {
    depends_on  = [null_resource.setup_nfs_disk]
    count       = var.storage_type == "nfs" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
        bastion_host = var.jump_host
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
        bastion_host = var.jump_host
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

