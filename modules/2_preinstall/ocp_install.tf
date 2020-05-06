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

resource "null_resource" "ocp_init" {
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
            "mkdir -p ~/openstack-upi && cd ~/openstack-upi",
            "wget ${var.openshift_install_tarball}",
            "tar -xvf openshift-install-linux*.tar.gz",
            "./openshift-install version --log-level ${var.log_level}",
        ]
    }
}

locals {
    install_cfg = {
        pull_secret             = var.pull_secret
        public_ssh_key          = var.public_key
        cluster_id              = var.cluster_id
        cluster_domain          = var.cluster_domain
        master_count            = var.master_count
    }
}

resource "null_resource" "ocp_install_config" {
    depends_on = [null_resource.ocp_init]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    # SETUP HTTP SERVER
    provisioner "remote-exec" {
        inline = [
            "sudo cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.orig",
            "sudo sed -i 's/Listen 80/Listen 8080/g' /etc/httpd/conf/httpd.conf",
            "sudo firewall-cmd --permanent --add-port=8080/tcp",
            "sudo firewall-cmd --reload",
            "sudo systemctl enable --now httpd",
            "sudo systemctl restart httpd"
        ]
    }
    #INSTALL-CONFIG
    provisioner "file" {
        content      = templatefile("${path.module}/templates/install-config.tpl",local.install_cfg)
        destination = "/tmp/cp4tf_install-config.tpl"
    }
    provisioner "remote-exec" {
        inline = [
            "cp /tmp/cp4tf_install-config.tpl ~/openstack-upi/install-config.yaml",
            "sudo cp ~/openstack-upi/install-config.yaml /var/www/html/install-config.yaml",
            "sudo chmod 755 /var/www/html/install-config.yaml",
            "sudo systemctl restart httpd"
        ]
    }
    
}


resource "null_resource" "ocp_manifest" {
    depends_on = [null_resource.ocp_install_config]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    #GENERATE MANIFEST
    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi && ./openshift-install create manifests --log-level ${var.log_level}",
            #Remove the control-plane Machines and compute MachineSets, because we'll be providing those ourselves.
            "rm -f openshift/99_openshift-cluster-api_master-machines-*.yaml openshift/99_openshift-cluster-api_worker-machineset-*.yaml",
            #Update the scheduler configuration to keep router pods and other workloads off the control-plane nodes.
            "sed -i 's/mastersSchedulable: true/mastersSchedulable: False/g' manifests/cluster-scheduler-02-config.yml"
        ]
    }
}

resource "null_resource" "ocp_ignition" {
    depends_on = [null_resource.ocp_manifest]
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
            "OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE=${var.release_image_override} ./openshift-install create ignition-configs --log-level ${var.log_level}"
        ]
    }
}

resource "null_resource" "ocp_ignition_update" {
    depends_on = [null_resource.ocp_ignition]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        source      = "${path.module}/scripts/update_ignition_bootstrap.py"
        destination = "/tmp/update_ignition_bootstrap.py"
    }

    #GENERATE MANIFEST
    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi",
            "python3 /tmp/update_ignition_bootstrap.py",
            "sudo cp bootstrap.ign /var/www/html/bootstrap.ign",
            "sudo chmod 755 /var/www/html/bootstrap.ign",
            "sudo cp master.ign /var/www/html/master.ign",
            "sudo chmod 755 /var/www/html/master.ign",
            "sudo cp worker.ign /var/www/html/worker.ign",
            "sudo chmod 755 /var/www/html/worker.ign",
            "sudo systemctl restart httpd"
        ]
    }
}

