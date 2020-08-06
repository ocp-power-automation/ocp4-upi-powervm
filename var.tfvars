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
connection_timeout          = 45
jump_host                   = ""

bastion                     = {instance_type    = "medium", image_id     = "daa5d3f4-ab66-4b2d-9f3d-77bd61774419"}
bootstrap                   = {instance_type    = "medium", image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 1}
master                      = {instance_type    = "medium",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 3}
worker                      = {instance_type    = "large",  image_id     = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4",  "count"   = 2}


### OpenShift variables
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.4/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.4/openshift-client-linux.tar.gz"

#release_image_override = ""

pull_secret_file = "data/pull-secret.txt"
cluster_domain = "example.com"
cluster_id_prefix = "test"
cluster_id        = ""

### Local registry variables
enable_local_registry = false  #Set to true to enable usage of the local registry for restricted network install.

#local_registry_image = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
#ocp_release_tag      = "4.4.9-ppc64le"

dns_forwarders      = "8.8.8.8; 8.8.4.4"
mount_etcd_ramdisk  = false
installer_log_level = "info"
ansible_extra_options = "-v"
rhcos_kernel_options  = []
sysctl_tuned_options  = false
#sysctl_options = ["kernel.shmmni = 16384", "net.ipv4.tcp_tw_reuse = 1"]
#match_array = <<EOF
#- label: node-role.kubernetes.io/master
#- label: icp4data
#  value: database-db2oltp
#  type: pod
#- label: disk
#  value: ssd
#EOF
chrony_config = true
#chrony_config_servers = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]

#helpernode_tag = "5eab3db53976bb16be582f2edc2de02f7510050d"
#install_playbook_tag = "54a781e4f50dab41f9256cfc3b3c45f2f928f9c4"

## Set up a squid proxy server on the bastion node.
setup_squid_proxy       = false

## N/A when `setup_squid_proxy = true`, set `setup_squid_proxy = false` when using external proxy.
## Uncomment any one of the below formats to use external proxy. Default 'port' will be 3128 if not specified. Not authenticated if 'user' is not specified.
#proxy = {}
#proxy = {server = "hostname_or_ip"}
#proxy = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}

storage_type    = "nfs"
volume_size = "300" # Value in GB
volume_storage_template = ""

#upgrade_image = ""
#upgrade_pause_time = "90"
#upgrade_delay_time = "600"
