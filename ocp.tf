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

provider "openstack" {
    user_name   = var.user_name
    password    = var.password
    tenant_name = var.tenant_name
    domain_name = var.domain_name
    auth_url    = var.auth_url
    insecure    = var.insecure
}

resource "random_id" "label" {
    byte_length = "2" # Since we use the hex, the word lenght would double
    prefix = "${var.cluster_id_prefix}-"
}

module "bastion" {
    source                          = "./modules/1_bastion"

    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
    bastion                         = var.bastion
    network_name                    = var.network_name
    scg_id                          = var.scg_id
    openstack_availability_zone     = var.openstack_availability_zone
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    public_key                      = local.public_key
    create_keypair                  = local.create_keypair
    keypair_name                    = "${random_id.label.hex}-keypair"
    ssh_agent                       = var.ssh_agent
    rhel_subscription_username      = var.rhel_subscription_username
    rhel_subscription_password      = var.rhel_subscription_password
}

module "preinstall" {
    source                          = "./modules/2_preinstall"

    bastion_ip                      = module.bastion.bastion_ip
    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    public_key                      = local.public_key
    ssh_agent                       = var.ssh_agent
    pull_secret                     = file(coalesce(var.pull_secret_file, "/dev/null"))
    openshift_install_tarball       = var.openshift_install_tarball
    master_count                    = var.master["count"]
    release_image_override          = var.release_image_override
}

module "network" {
    source                          = "./modules/3_network"

    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
    network_name                    = var.network_name
    master_count                    = var.master["count"]
    worker_count                    = var.worker["count"]
    bastion_ip                      = module.bastion.bastion_ip
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    ssh_agent                       = var.ssh_agent
    network_type                    = var.network_type
}

module "nodes" {
    source                          = "./modules/4_nodes"

    bootstrap_ign_url               = module.preinstall.bootstrap_ign_url
    master_ign_url                  = module.preinstall.master_ign_url
    worker_ign_url                  = module.preinstall.worker_ign_url
    bastion_ip                      = module.bastion.bastion_ip
    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
    bootstrap                       = var.bootstrap
    master                          = var.master
    worker                          = var.worker
    scg_id                          = var.scg_id
    openstack_availability_zone     = var.openstack_availability_zone
    bootstrap_port_id               = module.network.bootstrap_port_id
    master_port_ids                 = module.network.master_port_ids
    worker_port_ids                 = module.network.worker_port_ids
}

module "dns_haproxy" {
    source                          = "./modules/5_dns_haproxy"

    cluster_domain                  = var.cluster_domain
    cluster_id                      = "${random_id.label.hex}"
    bootstrap_ip                    = module.nodes.bootstrap_ip
    master_ips                      = module.nodes.master_ips
    worker_ips                      = module.nodes.worker_ips
    bastion_ip                      = module.bastion.bastion_ip
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    ssh_agent                       = var.ssh_agent
    dns_enabled                     = var.dns_enabled
}

module "install" {
    source                          = "./modules/6_install"

    bootstrap_ip                    = module.nodes.bootstrap_ip
    bastion_ip                      = module.bastion.bastion_ip
    master_ips                      = module.nodes.master_ips
    worker_ips                      = module.nodes.worker_ips
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    ssh_agent                       = var.ssh_agent
}

module "storage" {
    source                          = "./modules/7_storage"

    install_status                  = module.install.install_status
    cluster_id                      = "${random_id.label.hex}"
    bastion_ip                      = module.bastion.bastion_ip
    bastion_id                      = module.bastion.bastion_id
    storage_type                    = var.storage_type
    storageclass_name               = var.storageclass_name
    volume_size                     = var.volume_size
    volume_storage_template         = var.volume_storage_template
    rhel_username                   = var.rhel_username
    private_key                     = local.private_key
    ssh_agent                       = var.ssh_agent
}

