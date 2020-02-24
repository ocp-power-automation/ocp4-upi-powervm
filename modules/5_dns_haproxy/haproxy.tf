locals {
    bootstrap_entry = [{name = "${var.cluster_id}-bootstrap", ip = var.bootstrap_ip}]
    master_entries  = [for ix in range(length(var.master_ips)): {name = "${var.cluster_id}-master-${ix} ", ip = var.master_ips[ix]}]
    worker_entries  = [for ix in range(length(var.worker_ips)): {name = "${var.cluster_id}-worker-${ix} ", ip = var.worker_ips[ix]}]

    haproxy_config = {
        api_servers = concat(local.bootstrap_entry, local.master_entries),
        workers     = local.worker_entries
    }
}

resource "null_resource" "setup_haproxy" {
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }

    provisioner "file" {
        content     = templatefile("${path.module}/templates/haproxy.cfg", local.haproxy_config)
        destination = "/tmp/haproxy.cfg"
    }

    provisioner "remote-exec" {
        inline = [
            "sudo yum install -y haproxy",
            "sudo cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.orig",
            "sudo cp /tmp/haproxy.cfg /etc/haproxy/haproxy.cfg",
            "sudo chmod 644 /etc/haproxy/haproxy.cfg",
            "sudo firewall-cmd --permanent --add-service=http --add-service=https",
            "sudo firewall-cmd --permanent --add-port=6443/tcp --add-port=443/tcp --add-port=22623/tcp",
            "sudo firewall-cmd --reload",
            "sudo setsebool -P haproxy_connect_any=1",
            "sudo systemctl enable --now haproxy",
            "sudo systemctl restart haproxy"
        ]
    }
}
