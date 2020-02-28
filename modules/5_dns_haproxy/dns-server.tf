locals {
    script_cfg = {
        bastion_ip = var.bastion_ip
        sourcedir = "$HOME/setup-files/dns-setup"
    }
}

# Setup BIND.
resource "null_resource" "do_setup" {
    count       = var.dns_enabled == "true" ? 1 : 0
    connection {
        type        = "ssh"
        user        = var.rhel_username
        host        = var.bastion_ip
        private_key = var.private_key
        agent       = var.ssh_agent
        timeout     = "15m"
    }
    provisioner "remote-exec" {
        inline  = [
            "rm -rf ${local.script_cfg.sourcedir}",
            "mkdir -p ${local.script_cfg.sourcedir}"
        ]
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/dns-enable.sh", local.script_cfg)
        destination = "${local.script_cfg.sourcedir}/dns-enable.sh"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/dns-disable.sh", local.script_cfg)
        destination = "${local.script_cfg.sourcedir}/dns-disable.sh"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/named.conf", local.named_cfg)
        destination = "${local.script_cfg.sourcedir}/named.conf"
    }
    provisioner "file" {
        content     = templatefile("${path.module}/templates/cluster-zone.db", local.named_cfg)
        destination = "${local.script_cfg.sourcedir}/cluster-zone.db"
    }
    provisioner "remote-exec" {
        inline  = [
            "chmod +x ${local.script_cfg.sourcedir}/dns-enable.sh",
            "${local.script_cfg.sourcedir}/dns-enable.sh",
        ]
    }
    provisioner "remote-exec" {
        when    = destroy
        on_failure = continue
        inline  = [
            "chmod +x ${local.script_cfg.sourcedir}/dns-disable.sh",
            "${local.script_cfg.sourcedir}/dns-disable.sh || true",
            "rmdir --ignore-fail-on-non-empty ${local.script_cfg.sourcedir}"
        ]
    }
}
