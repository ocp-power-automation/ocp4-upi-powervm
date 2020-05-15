### Configure the OpenStack Provider
auth_url                    = "https://<HOSTNAME>:5000/v3/"
user_name                   = ""
password                    = ""
tenant_name                 = "tenant_name"
domain_name                 = "Default"
openstack_availability_zone = ""

### Configure the Instance details
network_name                = "network_name"
#network_type               = "SRIOV"
#scg_id                      = "df21cec9-c244-4d3d-b927-df1518672e87"
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
master                      = {instance_type    = "medium",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 3}
worker                      = {instance_type    = "large",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 2}

### OpenShift variables
openshift_install_tarball = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.4.0-0.nightly-ppc64le-2020-05-13-222456/openshift-install-linux.tar.gz"
openshift_client_tarball = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.4.0-0.nightly-ppc64le-2020-05-13-222456/openshift-client-linux.tar.gz"

#release_image_override = "quay.io/openshift-release-dev/ocp-release-nightly:4.4.0-0.nightly-ppc64le-2020-05-13-222456"

pull_secret_file = "data/pull-secret.txt"
cluster_domain = "example.com"
cluster_id_prefix = "test"

dns_forwarders = "8.8.8.8; 8.8.4.4"
#installer_log_level = "info"

## Currently master branch has support for ppc64le; We will use current(May 15, 2020) commit# which is stable.
#helpernode_tag = "d6ad30574619ae6427cad9662fe3a4a896a9af11"

storage_type    = "nfs"
volume_size = "300" # Value in GB
volume_storage_template = ""
cluster_id_prefix = "test"
