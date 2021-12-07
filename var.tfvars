### PowerVC Details
auth_url                    = "<https://<HOSTNAME>:5000/v3/>"
user_name                   = "<powervc-login-user-name>"
password                    = "<powervc-login-user-password>"
tenant_name                 = "<tenant_name>"
domain_name                 = "Default"
openstack_availability_zone = ""

network_name                = "<network_name>"

### OpenShift Cluster Details

bastion                     = {instance_type    = "<bastion-compute-template>",   image_id    = "<image-uuid-rhel>",   "count"   = 1}
bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 1}
master                      = {instance_type    = "<master-compute-template>",    image_id    = "<image-uuid-rhcos>",  "count"   = 3}
worker                      = {instance_type    = "<worker-compute-template>",    image_id    = "<image-uuid-rhcos>",  "count"   = 2}
# With all optional attributes
# bastion                     = {instance_type    = "<bastion-compute-template>",   image_id    = "<image-uuid-rhel>",   availability_zone = "<availability zone>",  "count"   = 1, fixed_ip_v4 = "<IPv4 address>"}
# bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>",  availability_zone = "<availability zone>",  "count"   = 1}
# master                      = {instance_type    = "<master-compute-template>",    image_id    = "<image-uuid-rhcos>",  availability_zone = "<availability zone>",  "count"   = 3, data_volume_count  = 0, data_volume_size  = 100}
# worker                      = {instance_type    = "<worker-compute-template>",    image_id    = "<image-uuid-rhcos>",  availability_zone = "<availability zone>",  "count"   = 2, data_volume_count  = 0, data_volume_size  = 100}


rhel_username               = "root"
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
rhel_subscription_username  = "<subscription-id>"          #Leave this as-is if using CentOS as bastion image
rhel_subscription_password  = "<subscription-password>"    #Leave this as-is if using CentOS as bastion image
rhel_subscription_org           = ""                       # Define it only when using activationkey for RHEL subscription
rhel_subscription_activationkey = ""                       # Define it only when using activationkey for RHEL subscription

connection_timeout          = 45
jump_host                   = ""

### OpenShift Installation Details

openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-client-linux.tar.gz"
pull_secret_file            = "data/pull-secret.txt"

cluster_domain              = "ibm.com"  # Set domain to nip.io or xip.io if you prefer using online wildcard domain and avoid modifying /etc/hosts
cluster_id_prefix           = "test-ocp" # Set it to empty if just want to use cluster_id without prefix
cluster_id                  = ""         # It will use random generated id with cluster_id_prefix if this is not set


### Misc Customizations

#network_type               = "SRIOV"
#scg_id                     = "df21cec9-c244-4d3d-b927-df1518672e87"
#sriov_vnic_failover_vfs    = 1
#sriov_capacity             = 0.02

#enable_local_registry      = false  #Set to true to enable usage of local registry for restricted network install.
#local_registry_image       = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
#ocp_release_tag            = "4.4.9-ppc64le"
#ocp_release_name           = "ocp-release"
#release_image_override     = ""


#helpernode_repo            = "https://github.com/RedHatOfficial/ocp4-helpernode"
#helpernode_tag             = ""
#install_playbook_repo      = "https://github.com/ocp-power-automation/ocp4-playbooks"
#install_playbook_tag       = ""

#installer_log_level        = "info"
#ansible_extra_options      = "-v"
#ansible_repo_name          = "ansible-2.9-for-rhel-8-ppc64le-rpms"
#dns_forwarders             = "1.1.1.1; 9.9.9.9"
#rhcos_pre_kernel_options   = []
#rhcos_kernel_options       = []
#chrony_config              = true
#chrony_config_servers      = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]

#setup_squid_proxy          = false

## N/A when `setup_squid_proxy = true`, set `setup_squid_proxy = false` when using external proxy.
#proxy                      = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}


# mount_etcd_ramdisk  = false


#storage_type                = "nfs"
#volume_size                 = "300" # Value in GB
#volume_storage_template     = ""

#upgrade_version            = ""
#upgrade_channel            = ""  #(stable-4.x, fast-4.x, candidate-4.x) eg. stable-4.5
#upgrade_image               = "" #quay.io/openshift-release-dev/ocp-release@sha256:xyz.."
#upgrade_pause_time         = "90"
#upgrade_delay_time         = "600"

#cni_network_provider       = "OpenshiftSDN"
#cluster_network_cidr        = "10.128.0.0/14"
#cluster_network_hostprefix  = "23"
#service_network             = "172.30.0.0/16"
