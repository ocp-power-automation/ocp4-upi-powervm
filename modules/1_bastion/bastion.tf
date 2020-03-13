resource "openstack_compute_keypair_v2" "key-pair" {
    count       = var.create_keypair
    name        = var.keypair_name
    public_key  = var.public_key
}


resource "openstack_compute_instance_v2" "bastion" {
    name            = "${var.cluster_id}-bastion"
    image_id        = var.bastion["image_id"]
    flavor_name     = var.bastion["instance_type"]
    key_pair        = openstack_compute_keypair_v2.key-pair.0.name
    network {
        name    = var.network_name
    }
    availability_zone = var.openstack_availability_zone
}


resource "null_resource" "check_bastion" {
    provisioner "remote-exec" {
        connection {
            host        = openstack_compute_instance_v2.bastion.access_ip_v4
            user        = var.rhel_username
            private_key = var.private_key
            agent       = var.ssh_agent
            timeout     = "15m"
        }
        inline = [
          "whoami",
        ]
    }
}

resource "null_resource" "bastion_init" {
    depends_on = [null_resource.check_bastion]
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = openstack_compute_instance_v2.bastion.access_ip_v4
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        when = destroy
        inline = [
            "sudo subscription-manager unregister",
            "sudo subscription-manager remove --all",
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
            "echo ' - preserve_hostname: true' | sudo tee -a /etc/cloud/cloud.cfg  > /dev/null",
            "sudo hostname -F /etc/hostname",
            "echo 'vm.max_map_count = 262144' | sudo tee --append /etc/sysctl.conf > /dev/null",
            "sudo sysctl -p",
            "sudo subscription-manager clean",
            "sudo subscription-manager register --username=${var.rhel_subscription_username} --password=${var.rhel_subscription_password} --force",
            "sudo subscription-manager refresh",
            "sudo subscription-manager attach --auto",
            "#sudo yum update -y --skip-broken",
            "sudo yum install -y wget jq git net-tools bind-utils vim python3 httpd tar",
            "sudo systemctl enable firewalld",
            "sudo systemctl start firewalld"
        ]
    }
    provisioner "remote-exec" {
        inline = [
            "sudo rm -rf /tmp/terraform_*"
        ]
    }
}
