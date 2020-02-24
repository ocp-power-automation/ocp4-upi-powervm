locals {
    setup_dir_name          = "dns-setup"
    setup_remote_dir        = "$HOME/setup-files"
    local_temp_render_dir   = "/tmp/setup-files"
}

# Render BIND config files:
resource "local_file" "named_conf" {
    filename             = "${local.local_temp_render_dir}/${local.setup_dir_name}/named.conf"
    sensitive_content    = templatefile("${path.module}/template-files/named.conf", local.named_cfg)
    file_permission      = "0644"
    directory_permission = "0755"
}

resource "local_file" "cluster_zone_db" {
    filename        = "${local.local_temp_render_dir}/${local.setup_dir_name}/cluster-zone.db"
    content    = templatefile("${path.module}/template-files/cluster-zone.db", local.named_cfg)
    file_permission      = "0644"
    directory_permission = "0755"
}

locals {
    script_cfg = {
        bastion_ip = var.bastion_ip
        sourcedir = "${local.setup_remote_dir}/${local.setup_dir_name}"
    }
}

resource local_file dns_script {
    filename   = "${local.local_temp_render_dir}/${local.setup_dir_name}/dns-enable.sh"
    content    = templatefile("${path.module}/scripts/dns-enable.sh", local.script_cfg)
    file_permission      = "0644"
    directory_permission = "0755"
}

# Setup BIND.
resource "null_resource" "do_setup" {
    depends_on = [local_file.named_conf, local_file.cluster_zone_db]

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
            "rm -rf ${local.setup_remote_dir}/${local.setup_dir_name}",
            "mkdir -p ${local.setup_remote_dir}/${local.setup_dir_name}"
        ]
    }

    provisioner "file" {
        source      = "${local.local_temp_render_dir}/${local.setup_dir_name}/"
        destination = "${local.setup_remote_dir}/${local.setup_dir_name}"
    }

    provisioner "remote-exec" {
        inline = [
            "chmod +x ${local.setup_remote_dir}/${local.setup_dir_name}/*.sh",
            "${local.setup_remote_dir}/${local.setup_dir_name}/dns-enable.sh",
        ]
    }
}
