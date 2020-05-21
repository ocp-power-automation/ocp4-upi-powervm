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
    vars_yaml = {
        cluster_domain  = var.cluster_domain
        cluster_id      = var.cluster_id
        bastion_ip      = var.bastion_ip
        forwarders      = var.dns_forwarders
        gateway_ip      = var.gateway_ip
        netmask         = cidrnetmask(var.cidr)
        broadcast       = cidrhost(var.cidr,-1)
        ipid            = cidrhost(var.cidr, 0)
        pool            = var.allocation_pools[0]

        bootstrap_info  = {
            ip = var.bootstrap_ip,
            mac = var.bootstrap_mac,
            name = "bootstrap.${var.cluster_id}.${var.cluster_domain}"
        }
        master_info     = [ for ix in range(length(var.master_ips)) :
            {
                ip = var.master_ips[ix],
                mac = var.master_macs[ix],
                name = "master-${ix}.${var.cluster_id}.${var.cluster_domain}"
            }
        ]
        worker_info     = [ for ix in range(length(var.worker_ips)) :
            {
                ip = var.worker_ips[ix],
                mac = var.worker_macs[ix],
                name = "worker-${ix}.${var.cluster_id}.${var.cluster_domain}"
            }
        ]

        client_tarball  = var.openshift_client_tarball
        install_tarball = var.openshift_install_tarball
    }

    install_cfg = {
        pull_secret             = var.pull_secret
        public_ssh_key          = var.public_key
        cluster_id              = var.cluster_id
        cluster_domain          = var.cluster_domain
        master_count            = var.master_count
    }
}

resource "null_resource" "config" {
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
            "rm -rf ocp4-helpernode",
            "echo 'Cloning into ocp4-helpernode...'",
            "git clone https://github.com/RedHatOfficial/ocp4-helpernode >/dev/null",
            "cd ocp4-helpernode && git checkout ${var.helpernode_tag}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/vars.yaml", local.vars_yaml)
        destination = "~/ocp4-helpernode/vars.yaml"
    }
    provisioner "remote-exec" {
        inline = [
            "echo 'Running ocp4-helpernode playbook...'",
            "cd ocp4-helpernode && ansible-playbook -e @vars.yaml tasks/main.yml > ocp4-helpernode-ansible.log 2>&1"
        ]
    }
}

resource "null_resource" "ocp_init" {
    depends_on = [null_resource.config]

    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    #INSTALL-CONFIG
    provisioner "file" {
        content      = templatefile("${path.module}/templates/install-config.tpl", local.install_cfg)
        destination = "/tmp/ocp4tf_install-config.tpl"
    }
    provisioner "file" {
        source      = "${path.module}/scripts/update_ignition_bootstrap.py"
        destination = "/tmp/update_ignition_bootstrap.py"
    }

    provisioner "remote-exec" {
        inline = [
            "rm -rf ~/openstack-upi && mkdir ~/openstack-upi",
            "cp /tmp/ocp4tf_install-config.tpl ~/openstack-upi/install-config.yaml",
        ]
    }

    #create manifests
    provisioner "remote-exec" {
        inline = [
            "openshift-install create manifests  --dir ~/openstack-upi --log-level ${var.log_level}"
        ]
    }

    #create ignition-configs
    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi",
            #Remove the control-plane Machines and compute MachineSets, because we'll be providing those ourselves.
            "rm -f openshift/99_openshift-cluster-api_master-machines-*.yaml openshift/99_openshift-cluster-api_worker-machineset-*.yaml",
            #Update the scheduler configuration to keep router pods and other workloads off the control-plane nodes.
            "sed -i 's/mastersSchedulable: true/mastersSchedulable: False/g' manifests/cluster-scheduler-02-config.yml",

            "OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE=${var.release_image_override} openshift-install create ignition-configs --log-level ${var.log_level}"
        ]
    }

    provisioner "remote-exec" {
        inline = [
            "cd ~/openstack-upi && python3 /tmp/update_ignition_bootstrap.py",
        ]
    }

    provisioner "remote-exec" {
        inline = [
            "cp ~/openstack-upi/*.ign /var/www/html/ignition/",
            "restorecon -vR /var/www/html/",
            "chmod o+r /var/www/html/ignition/*.ign"
        ]
    }
}

resource "null_resource" "check_bootstrap" {
    depends_on = [null_resource.ocp_init]

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
          "if lsmod|grep -q 'ibmveth'; then sudo sysctl -w net.ipv4.route.min_pmtu=1450; sudo sysctl -w net.ipv4.ip_no_pmtu_disc=1; echo 'net.ipv4.route.min_pmtu = 1450' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null; echo 'net.ipv4.ip_no_pmtu_disc = 1' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null; fi"
        ]
    }
}

resource "null_resource" "check_master" {
    depends_on = [null_resource.ocp_init]

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
          "if lsmod|grep -q 'ibmveth'; then sudo sysctl -w net.ipv4.route.min_pmtu=1450; sudo sysctl -w net.ipv4.ip_no_pmtu_disc=1; echo 'net.ipv4.route.min_pmtu = 1450' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null; echo 'net.ipv4.ip_no_pmtu_disc = 1' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null; fi"
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
            "openshift-install wait-for bootstrap-complete --dir ~/openstack-upi --log-level ${var.log_level}"
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
          "if lsmod|grep -q 'ibmveth'; then sudo sysctl -w net.ipv4.route.min_pmtu=1450; sudo sysctl -w net.ipv4.ip_no_pmtu_disc=1; echo 'net.ipv4.route.min_pmtu = 1450' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null; echo 'net.ipv4.ip_no_pmtu_disc = 1' | sudo tee --append /etc/sysctl.d/88-sysctl.conf > /dev/null; fi"
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
            "while [ $(oc get nodes | grep -w worker | grep -w  'Ready' | wc -l) != ${length(var.worker_ips)} ]; do oc get csr -ojson | jq -r '.items[] | select(.status == {} ) | .metadata.name' | xargs oc adm certificate approve; sleep 30; echo 'Worker not Ready, sleeping for 30s..'; done"
        ]
    }
}

resource "null_resource" "wait_install" {
    depends_on = [null_resource.approve_worker_csr]
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
            "openshift-install wait-for install-complete --dir ~/openstack-upi --log-level ${var.log_level}"
        ]
    }

    # Force copy kubeconfig file again after install
    provisioner "remote-exec" {
        inline = [
            "\\cp ~/openstack-upi/auth/kubeconfig ~/.kube/config"
        ]
    }
}

resource "null_resource" "patch_image_registry" {
    depends_on = [null_resource.wait_install]
    count       = var.storage_type != "nfs" ? 1 : 0
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
