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

################################################################
# Configure the OpenStack Provider
################################################################
variable "user_name" {
    description = "The user name used to connect to OpenStack/PowerVC"
    default = "my_user_name"
}

variable "password" {
    description = "The password for the user"
    default = "my_password"
}

variable "tenant_name" {
    description = "The name of the project (a.k.a. tenant) used"
    default = "ibm-default"
}

variable "domain_name" {
    description = "The domain to be used"
    default = "Default"
}

variable "auth_url" {
    description = "The endpoint URL used to connect to OpenStack/PowerVC"
    default = "https://<HOSTNAME>:5000/v3/"
}

variable "insecure" {
  default = "true" # OS_INSECURE
}

variable "openstack_availability_zone" {
    description = "The name of Availability Zone for deploy operation"
    default = ""
}


################################################################
# Configure the Instance details
################################################################

variable "bastion" {
    # only one node is supported
    default = {
        instance_type   = "m1.xlarge"
        image_id        = "daa5d3f4-ab66-4b2d-9f3d-77bd61774419"
    }
}
variable "bootstrap" {
    default = {
        # only one node is supported
        count = 1
        instance_type = "m1.xlarge"
        # rhcos image id
        image_id      = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
    }
}

variable "master" {
    default = {
        count = 3
        instance_type = "m1.xlarge"
        # rhcos image id
        image_id      = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
    }
}

variable "worker" {
    default = {
        count = 2
        instance_type = "m1.xlarge"
        # rhcos image id
        image_id      = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4"
    }
}

variable "network_name" {
    description = "The name of the network to be used for deploy operations"
    default = "my_network_name"
}

variable "network_type" {
    #Eg: SEA or SRIOV
    default = "SEA"
    description = "Specify the name of the network adapter type to use for creating hosts"
}

variable "scg_id" {
    description = "The id of PowerVC Storage Connectivity Group to use for all nodes"
    default = ""
}

variable "rhel_username" {
    default = "root"
}

variable "keypair_name" {
  # Set this variable to the name of an already generated
  # keypair to use it instead of creating a new one.
  default = ""
}

variable "public_key_file" {
    description = "Path to public key file"
    # if empty, will default to ${path.cwd}/data/id_rsa.pub
    default     = ""
}

variable "private_key_file" {
    description = "Path to private key file"
    # if empty, will default to ${path.cwd}/data/id_rsa
    default     = ""
}

variable "private_key" {
    description = "content of private ssh key"
    # if empty string will read contents of file at var.private_key_file
    default = ""
}

variable "public_key" {
    description = "Public key"
    # if empty string will read contents of file at var.public_key_file
    default     = ""
}

variable "rhel_subscription_username" {
    default = ""
}

variable "rhel_subscription_password" {
    default = ""
}

variable "rhcos_kernel_options" {
    description = "List of kernel arguments for the cluster nodes"
    default     = []
}

variable "sysctl_tuned_options" {
    description = "Set to true to apply sysctl options via tuned operator. Default: false"
    default     = false
}

variable "sysctl_options" {
    description = "List of sysctl options to apply."
    default     = []
}

variable "match_array" {
    description = "Criteria for node/pod selection."
    default     = <<EOF
EOF
}

variable "chrony_config" {
    description = "Set to true to setup time synchronization and setup chrony. Default: false"
    default     = true
}

variable "chrony_config_servers" {
    description = "List of ntp servers and options to apply"
    default     = []
    # example: chrony_config_servers = [ {server = "10.3.21.254", options = "iburst"}, {server = "10.5.21.254", options = "iburst"} ]
}

################################################################
### Instrumentation
################################################################
variable "ssh_agent" {
    description = "Enable or disable SSH Agent. Can correct some connectivity issues. Default: false"
    default     = false
}

variable "connection_timeout" {
    description = "Timeout in minutes for SSH connections"
    default     = 45
}

variable "jump_host" {
    description = "Jump server hostname/IP to be used for SSH connections"
    default     = ""
}

variable "installer_log_level" {
    description = "Set the log level required for openshift-install commands"
    default = "info"
}

variable "helpernode_repo" {
    description = "Set the repo URL for using ocp4-helpernode"
    # Repo for running ocp4 helpernode setup steps.
    default = "https://github.com/RedHatOfficial/ocp4-helpernode"
}

variable "helpernode_tag" {
    description = "Set the branch/tag name or commit# for using ocp4-helpernode repo"
    # Checkout level for https://github.com/RedHatOfficial/ocp4-helpernode which is used for setting up services required on bastion node
    default = "dd8a0767c677fc862e45b6d70e5d04656ced5d28"
}

variable "install_playbook_repo" {
    description = "Set the repo URL for using ocp4-playbooks"
    # Repo for running ocp4 installations steps.
    default = "https://github.com/ocp-power-automation/ocp4-playbooks"
}

variable "install_playbook_tag" {
    description = "Set the branch/tag name or commit# for using ocp4-playbooks repo"
    # Checkout level for https://github.com/ocp-power-automation/ocp4-playbooks which is used for running ocp4 installations steps
    default = "c6e6038dba0856e621697c876bd3a65927f46166"
}

variable "ansible_extra_options" {
    description = "Extra options string to append to ansible-playbook commands"
    default     = "-v"
}

locals {
    private_key_file    = var.private_key_file == "" ? "${path.cwd}/data/id_rsa" : var.private_key_file
    public_key_file     = var.public_key_file == "" ? "${path.cwd}/data/id_rsa.pub" : var.public_key_file
    private_key         = var.private_key == "" ? file(coalesce(local.private_key_file, "/dev/null")) : var.private_key
    public_key          = var.public_key == "" ? file(coalesce(local.public_key_file, "/dev/null")) : var.public_key
    create_keypair      = var.keypair_name == "" ? "1": "0"
}


################################################################
### OpenShift variables
################################################################
variable "openshift_install_tarball" {
    default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-install-linux.tar.gz"
}

variable "openshift_client_tarball" {
     default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-client-linux.tar.gz"
}

variable "release_image_override" {
    default = ""
}

variable "pull_secret_file" {
    default   = "data/pull-secret.txt"
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
variable "cluster_domain" {
    default   = "rhocp.com"
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
# Should not be more than 14 characters
variable "cluster_id_prefix" {
    default   = "test-ocp"
}
# Must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character
# Length cannot exceed 14 characters when combined with cluster_id_prefix
variable "cluster_id" {
    default   = ""
}

variable "dns_forwarders" {
    default   = "8.8.8.8; 8.8.4.4"
}

variable "mount_etcd_ramdisk" {
    description = "Whether mount etcd directory in the ramdisk (Only for dev/test) on low performance disk"
    default     = false
}

variable "setup_squid_proxy" {
    description = "Flag to install and configure squid proxy server on bastion node"
    default     = false
}

# Applicable only when `setup_squid_proxy = false`
variable proxy {
    description = "External proxy server details in a map of server, port(default=3128), user & password"
    default = {}
#    default = {
#        server = "10.10.1.166",
#        port = "3128"
#        user = "pxuser",
#        password = "pxpassword"
#    }
}

variable "storage_type" {
    #Supported values: nfs (other value won't setup a storageclass)
    default = "nfs"
}

variable "volume_size" {
    # If storage_type = nfs, a new volume of this size will be attached to the bastion node.
    # Value in GB
    default = "300"
}

variable "volume_storage_template" {
    # Storage template name or ID for creating the volume.
    default = ""
}

variable "upgrade_version" {
    description = "OCP upgrade version eg. 4.5.4"
    default = ""
}

variable "upgrade_channel" {
    description = "Upgrade channel having required version availble for cluster upgrade (stable-4.x, fast-4.x, candidate-4.x) eg. stable-4.5"
    default = ""
}

variable "upgrade_pause_time" {
    description = "Number of minutes to pause the playbook execution before starting to check the upgrade status once the upgrade command is executed."
    default = "90"
}

variable "upgrade_delay_time" {
    description = "Number of seconds to wait before re-checking the upgrade status once the playbook execution resumes."
    default = "600"
}

################################################################
# Local registry variables ( used only in disconnected install )
################################################################
variable "enable_local_registry" {
  description = "Set to true to enable usage of local registry for restricted network install."
  type = bool
  default = false
}

variable "local_registry_image" {
    description = "Name of the image used for creating the local registry container."
    default = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
}

variable "ocp_release_tag" {
    description = "The version of OpenShift you want to sync."
    default = "4.4.9-ppc64le"
}
