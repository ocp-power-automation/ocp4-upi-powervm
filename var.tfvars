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
rhcos_kernel_options        = []
bastion                     = {instance_type    = "medium", image_id     = "daa5d3f4-ab66-4b2d-9f3d-77bd61774419"}
bootstrap                   = {instance_type    = "medium", image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 1}
master                      = {instance_type    = "medium",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 3}
worker                      = {instance_type    = "large",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 2}


### OpenShift variables
openshift_install_tarball = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.4.0-0.nightly-ppc64le-2020-06-02-231523/openshift-install-linux.tar.gz"
openshift_client_tarball = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/4.4.0-0.nightly-ppc64le-2020-06-02-231523/openshift-client-linux.tar.gz"

#release_image_override = ""

pull_secret_file = "data/pull-secret.txt"
cluster_domain = "example.com"
cluster_id_prefix = "test"

dns_forwarders = "8.8.8.8; 8.8.4.4"
installer_log_level = "info"
ansible_extra_options = "-v"

#helpernode_tag = "fddbbc651153ef2966e5cb4d4167990b31c01ceb"
#install_playbook_tag = "3614f1f2b8a5a8db310e0990000c9c6b419ed4f3"

storage_type    = "nfs"
volume_size = "300" # Value in GB
volume_storage_template = ""

#upgrade_image = ""
#upgrade_pause_time = "90"
#upgrade_delay_time = "600"

