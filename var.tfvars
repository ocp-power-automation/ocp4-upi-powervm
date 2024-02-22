### PowerVC Details
auth_url                    = "<https://<HOSTNAME>:5000/v3/>"
user_name                   = "<powervc-login-user-name>"
password                    = "<powervc-login-user-password>"
tenant_name                 = "<tenant_name>"
domain_name                 = "Default"
openstack_availability_zone = ""

network_name = "<network_name>"

### OpenShift Cluster Details

bastion   = { instance_type = "<bastion-compute-template>", image_id = "<image-uuid-rhel>", "count" = 1 }
bootstrap = { instance_type = "<bootstrap-compute-template>", image_id = "<image-uuid-rhcos>", "count" = 1 }
master    = { instance_type = "<master-compute-template>", image_id = "<image-uuid-rhcos>", "count" = 3 }
worker    = { instance_type = "<worker-compute-template>", image_id = "<image-uuid-rhcos>", "count" = 2 }
# With all optional attributes
# bastion                     = {instance_type    = "<bastion-compute-template>",   image_id    = "<image-uuid-rhel>",   availability_zone = "<availability zone>",  "count"   = 1, fixed_ip_v4 = "<IPv4 address>"}
# bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>",  availability_zone = "<availability zone>",  "count"   = 1}
# master                      = {instance_type    = "<master-compute-template>",    image_id    = "<image-uuid-rhcos>",  availability_zone = "<availability zone>",  "count"   = 3, data_volume_count  = 0, data_volume_size  = 100}
# worker                      = {instance_type    = "<worker-compute-template>",    image_id    = "<image-uuid-rhcos>",  availability_zone = "<availability zone>",  "count"   = 2, data_volume_count  = 0, data_volume_size  = 100}


rhel_username                   = "root" #Set it to an appropriate username for non-root user access
public_key_file                 = "data/id_rsa.pub"
private_key_file                = "data/id_rsa"
rhel_subscription_username      = "<subscription-id>"       #Leave this as-is if using CentOS as bastion image
rhel_subscription_password      = "<subscription-password>" #Leave this as-is if using CentOS as bastion image
rhel_subscription_org           = ""                        # Define it only when using activationkey for RHEL subscription
rhel_subscription_activationkey = ""                        # Define it only when using activationkey for RHEL subscription

connection_timeout = 45
jump_host          = ""

### OpenShift Installation Details

openshift_install_tarball = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-install-linux.tar.gz"
openshift_client_tarball  = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-client-linux.tar.gz"
pull_secret_file          = "data/pull-secret.txt"

cluster_domain    = "ibm.com"  # Set domain to nip.io or xip.io if you prefer using online wildcard domain and avoid modifying /etc/hosts
cluster_id_prefix = "test-ocp" # Set it to empty if just want to use cluster_id without prefix
cluster_id        = ""         # It will use random generated id with cluster_id_prefix if this is not set
#fips_compliant             = false   # Set it true if you prefer to use FIPS enable in ocp deployment

### Misc Customizations

#network_type               = "SRIOV"
#scg_id                     = "df21cec9-c244-4d3d-b927-df1518672e87"
#sriov_vnic_failover_vfs    = 1
#sriov_capacity             = 0.02

#enable_local_registry      = false  #Set to true to enable usage of local registry for restricted network install.
#local_registry_image       = "docker.io/library/registry:2"
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

# sysctl_tuned_options        = true
# sysctl_options              = ["kernel.shmmni=16384","net.ipv4.tcp_tw_reuse=1"]
# match_array                 = <<EOF
#   - label: node-role.kubernetes.io/master
#   - label: icp4data
#     value: database-db2oltp
#     type: pod
#   - label: disk
#     value: ssd
# EOF

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
#upgrade_channel            = ""  #(stable-4.x, fast-4.x, candidate-4.x) eg. stable-4.11
#upgrade_image               = "" #quay.io/openshift-release-dev/ocp-release@sha256:xyz.."
#upgrade_pause_time         = "90"
#upgrade_delay_time         = "600"

#eus_upgrade_version        = ""
#eus_upgrade_channel        = ""  #(stable-4.x, fast-4.x, candidate-4.x, eus-4.x) eg. stable-4.11
#eus_upgrade_image          = ""  #(quay.io/openshift-release-dev/ocp-release@sha256:xyz..)
#eus_upstream               = ""  #https://ppc64le.ocp.releases.ci.openshift.org/graph

#cni_network_provider       = "OVNKubernetes"
#cluster_network_cidr        = "10.128.0.0/14"
#cluster_network_hostprefix  = "23"
#service_network             = "172.30.0.0/16"
#private_network_mtu         = "1450"

#luks_compliant              = false # Set it true if you prefer to use LUKS enable in OCP deployment
#luks_config                 = [ { thumbprint = "", url = "" } ]
#luks_filesystem_device      = "/dev/mapper/root"  #Set the Path of device to be luks encrypted
#luks_format                 = "xfs"  #Set the Format of the FileSystem to be luks encrypted
#luks_wipe_filesystem         = true  #Configures the FileSystem to be wiped
#luks_device                 = "/dev/disk/by-partlabel/root"  #Set the Path of luks encrypted partition
#luks_label                  = "luks-root"  #Set the value for user label of luks encrypted partition
#luks_options                = ["--cipher", "aes-cbc-essiv:sha256"]  #Set List of luks options for the luks encryption
#luks_wipe_volume             = true  #Configures the luks encrypted partition to be wiped
#luks_name                   = "root" #Set the value for the user label of Filesystem to be luks encrypted

#kdump_enable              = false # Set to true to enable the kdump on Cluster Nodes
#kdump_commandline_remove  = "hugepages hugepagesz slub_debug quiet log_buf_len swiotlb" # This option removes arguments from the current kdump command line
#kdump_commandline_append  = "irqpoll maxcpus=1 reset_devices cgroup_disable=memory mce=off numa=off udev.children-max=2 panic=10 rootflags=nofail acpi_no_memhotplug transparent_hugepage=never nokaslr novmcoredd hest_disable srcutree.big_cpu_lim=0" #This option appends arguments to the current kdump command line
#kdump_kexec_args          = "-s" #For adding any extra argument to pass to kexec command
#kdump_img                 = "vmlinuz" #For specifying image other than default kernel image
#kdump_log_path            = "/var/crash" #The file system path in which the kdump saves the vmcore file
#kdump_crash_kernel_memory = "2G-4G:384M,4G-16G:512M,16G-64G:1G,64G-128G:2G,128G-:4G" #The crashkernel memory reservation for kdump occurs during the system boot
