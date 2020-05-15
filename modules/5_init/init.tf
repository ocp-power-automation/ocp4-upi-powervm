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
        destination = "/tmp/cp4tf_install-config.tpl"
    }
    provisioner "file" {
        source      = "${path.module}/scripts/update_ignition_bootstrap.py"
        destination = "/tmp/update_ignition_bootstrap.py"
    }

    provisioner "remote-exec" {
        inline = [
            "rm -rf ~/openstack-upi && mkdir ~/openstack-upi",
            "cp /tmp/cp4tf_install-config.tpl ~/openstack-upi/install-config.yaml",
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
