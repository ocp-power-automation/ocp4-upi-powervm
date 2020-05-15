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

resource "openstack_compute_keypair_v2" "key-pair" {
    count       = var.create_keypair
    name        = var.keypair_name
    public_key  = var.public_key
}

resource "random_id" "label" {
    count       = var.scg_id == "" ? 0 : 1
    byte_length = "2"
}

resource "openstack_compute_flavor_v2" "bastion_scg" {
    count       = var.scg_id == "" ? 0 : 1
    name        = "${var.bastion["instance_type"]}-${random_id.label[0].hex}-scg"
    region      = data.openstack_compute_flavor_v2.bastion.region
    ram         = data.openstack_compute_flavor_v2.bastion.ram
    vcpus       = data.openstack_compute_flavor_v2.bastion.vcpus
    disk        = data.openstack_compute_flavor_v2.bastion.disk
    swap        = data.openstack_compute_flavor_v2.bastion.swap
    rx_tx_factor    = data.openstack_compute_flavor_v2.bastion.rx_tx_factor
    is_public   = data.openstack_compute_flavor_v2.bastion.is_public
    extra_specs = merge(data.openstack_compute_flavor_v2.bastion.extra_specs, {"powervm:storage_connectivity_group": var.scg_id})
}

data "openstack_compute_flavor_v2" "bastion" {
    name        = var.bastion["instance_type"]
}

resource "openstack_compute_instance_v2" "bastion" {
    name            = "${var.cluster_id}-bastion"
    image_id        = var.bastion["image_id"]
    flavor_id       = var.scg_id == "" ? data.openstack_compute_flavor_v2.bastion.id : openstack_compute_flavor_v2.bastion_scg[0].id
    key_pair        = openstack_compute_keypair_v2.key-pair.0.name
    network {
        name    = var.network_name
    }
    availability_zone = var.openstack_availability_zone

    provisioner "remote-exec" {
        connection {
            type        = "ssh"
            user        = var.rhel_username
            host        = self.access_ip_v4
            private_key = var.private_key
            agent       = var.ssh_agent
            timeout     = "15m"
        }

        when        = destroy
        on_failure  = continue
        inline = [
            "sudo subscription-manager unregister",
            "sudo subscription-manager remove --all",
        ]
    }
}


resource "null_resource" "bastion_init" {
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = openstack_compute_instance_v2.bastion.access_ip_v4
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline = [
            "whoami"
        ]
    }
    provisioner "file" {
        content = var.private_key
        destination = "~/.ssh/id_rsa"
    }
    provisioner "file" {
        content = var.public_key
        destination = "~/.ssh/id_rsa.pub"
    }
    provisioner "remote-exec" {
        inline = [
            "sudo chmod 600 ~/.ssh/id_rsa*",
            "sudo sed -i.bak -e 's/^ - set_hostname/# - set_hostname/' -e 's/^ - update_hostname/# - update_hostname/' /etc/cloud/cloud.cfg",
            "sudo hostnamectl set-hostname --static ${lower(var.cluster_id)}-bastion.${var.cluster_domain}",
            "echo 'HOSTNAME=${lower(var.cluster_id)}-bastion.${var.cluster_domain}' | sudo tee -a /etc/sysconfig/network > /dev/null",
            "sudo hostname -F /etc/hostname",
            "echo 'vm.max_map_count = 262144' | sudo tee --append /etc/sysctl.conf > /dev/null",
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo subscription-manager clean",
            "sudo subscription-manager register --username=${var.rhel_subscription_username} --password=${var.rhel_subscription_password} --force",
            "sudo subscription-manager refresh",
            "sudo subscription-manager attach --auto",
            "#sudo yum update -y --skip-broken",
            "sudo yum install -y wget jq git net-tools vim python3 tar"
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo pip3 install ansible -q"
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo systemctl unmask NetworkManager",
            "sudo systemctl start NetworkManager",
            "for i in $(nmcli device | grep unmanaged | awk '{print $1}'); do echo NM_CONTROLLED=yes | sudo tee -a /etc/sysconfig/network-scripts/ifcfg-$i; done",
            "sudo systemctl restart NetworkManager",
            "sudo systemctl enable NetworkManager"
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo rm -rf /tmp/terraform_*"
        ]
    }
}
