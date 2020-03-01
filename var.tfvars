# Configure the OpenStack Provider
auth_url                    = "https://<HOSTNAME>:5000/v3/"
user_name                   = ""
password                    = ""
tenant_name                 = "tenant_name"
domain_name                 = "Default"
openstack_availability_zone = ""

# Configure the Instance details
network_name                = "network_name"
rhel_username               = "root"
#keypair_name                = "mykeypair"
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
private_key                 = ""
public_key                  = ""
rhel_subscription_username  = ""
rhel_subscription_password  = ""
bastion                     = {instance_type    = "medium", image_id     = "daa5d3f4-ab66-4b2d-9f3d-77bd61774419"}
bootstrap                   = {instance_type    = "medium", image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 1}
master                      = {instance_type    = "large",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 3}
worker                      = {instance_type    = "large",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 2}

# OpenShift variables
openshift_install_tarball = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.3.0-0.nightly-ppc64le-2020-02-20-212303/openshift-install-linux-4.3.0-0.nightly-ppc64le-2020-02-20-212303.tar.gz"
release_image_override = ""
pull_secret_file = "data/pull-secret.txt"
cluster_domain = "example.com"

dns_enabled     = "true"

storage_type    = "nfs"
nfs_volume_size = "300" # Value in GB
cluster_id_prefix = "test"
