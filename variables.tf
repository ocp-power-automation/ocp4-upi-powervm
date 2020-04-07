################################################################
# Configure the OpenStack Provider
################################################################
variable "user_name" {
    description = "The user name used to connect to OpenStack"
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
    description = "The endpoint URL used to connect to OpenStack"
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

variable "rhel_subscription_username" {}

variable "rhel_subscription_password" {}

################################################################
### Instrumentation
################################################################
variable "ssh_agent" {
  description = "Enable or disable SSH Agent. Can correct some connectivity issues. Default: false"
  default     = false
}

variable "verbose" {
  # if anything is specified, it will be verbose.
  default = ""
}

locals {
    private_key_file    = "${var.private_key_file == "" ? "${path.cwd}/data/id_rsa" : "${var.private_key_file}" }"
    public_key_file     = "${var.public_key_file == "" ? "${path.cwd}/data/id_rsa.pub" : "${var.public_key_file}" }"
    private_key         = "${var.private_key == "" ? file(coalesce(local.private_key_file, "/dev/null")) : "${var.private_key}" }"
    public_key          = "${var.public_key == "" ? file(coalesce(local.public_key_file, "/dev/null")) : "${var.public_key}" }"
    create_keypair      = "${var.keypair_name == "" ? "1": "0"}"
}


################################################################
### OpenShift variables
################################################################
variable "openshift_install_tarball" {
    default = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.3.0-0.nightly-ppc64le-2020-02-13-160829/openshift-install-linux-4.3.0-0.nightly-ppc64le-2020-02-13-160829.tar.gz"
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

variable "dns_enabled" {
    default   = "true"
}

variable "storage_type" {
    default = "nfs"
}

variable "storageclass_name" {
    default = "managed-nfs-storage"
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

