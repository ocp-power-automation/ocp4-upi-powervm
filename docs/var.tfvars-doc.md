# How to use var.tfvars

- [How to use var.tfvars](#how-to-use-vartfvars)
  - [Introduction](#introduction)
    - [PowerVC Details](#powervc-details)
    - [OpenShift Cluster Details](#openshift-cluster-details)
    - [OpenShift Installation Details](#openshift-installation-details)
    - [Misc Customizations](#misc-customizations)


## Introduction

This guide gives an overview of the various terraform variables that are used for the deployment.
The default values are set in [variables.tf](../variables.tf)

### PowerVC Details

These set of variables specify the PowerVC details.

```
auth_url                    = "<https://<HOSTNAME>:5000/v3/>"
user_name                   = "<powervc-login-user-name>"
password                    = "<powervc-login-user-password>"
tenant_name                 = "<tenant_name>"
domain_name                 = "Default"
```

This variable specifies the network that will be used by the VMs
```
network_name                = "<network_name>"
```

This variable specifies the availability zone (PowerVC Host Group) in which to create the VMs. Leave it empty to use the "default" availability zone.
```
openstack_availability_zone = ""
```

### OpenShift Cluster Details

These set of variables specify the cluster capacity.

```
bastion                     = {instance_type    = "<bastion-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 1}
bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 1}
master                      = {instance_type    = "<master-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 3}
worker                      = {instance_type    = "<worker-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 2}
```

`instance_type` is the compute template to be used and `image_id` is the image UUID. `count` specifies the number of VMs that should be created for each type.

To enable high availability (HA) for cluster services running on the bastion set the bastion `count` value to 2. Note that in case of HA, the automation will not setup NFS storage. `count` of 1 for bastion implies the default non-HA bastion setup.

You can optionally set worker `count` value to 0 in which case all the cluster pods will be running on the master/supervisor nodes.
Ensure you use proper sizing for master/supervisor nodes to avoid resource starvation for containers.

`availability_zone` is an optional attribute for bastion, bootstrap, master and worker. If it is specified, the VM will be created in the specified `availability_zone`, otherwise value of `openstack_availability_zone` will be used.
```
bastion                     = {instance_type    = "<bastion-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 1}
bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>", availability_zone = "", "count"   = 1}
master                      = {instance_type    = "<master-compute-template>", image_id    = "<image-uuid-rhcos>", availability_zone = "master-zone",  "count"   = 3}
worker                      = {instance_type    = "<worker-compute-template>", image_id    = "<image-uuid-rhcos>", availability_zone = "worker-zone",  "count"   = 2}
```
Above will create the bastion in `openstack_availability_zone`, bootstrap in default availability zone, masters in `master-zone`, and workers in `worker-zone`.

To set a pre-defined IPv4 address for the bastion node, make use of the optional `fixed_ip_v4` in bastion variable as shown below. Ensure this address is within the given network subnet range and not already in use.
```
bastion                     = {instance_type    = "<bastion-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 1,  fixed_ip_v4 = "<IPv4 address>"}
```
For bastion HA with pre-defined IPs, here the `fixed_ip_v4` will be the VIP for bastions:
```
bastion                     = {instance_type    = "<bastion-compute-template>", image_id    = "<image-uuid-rhel>",  "count"   = 2,  fixed_ip_v4 = "<IPv4 address>", fixed_ips = ["<IPv4 address>", "<IPv4 address>"]}
```
To use predefined IPs for bootstrap, master and worker node, use the optional `fixed_ips` in bootstrap, master and worker variables, number of IPs have to match the count number as shown below:
```
bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 1, fixed_ips = ["<IPv4 address>"]}
master                      = {instance_type    = "<master-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 3, fixed_ips = ["<IPv4 address>", "<IPv4 address>", "<IPv4 address>"]}
worker                      = {instance_type    = "<worker-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 2, fixed_ips = ["<IPv4 address>", "<IPv4 address>"]}
```
To attach additional volumes to master or worker nodes, set the optional `data_volume_count` key to the number of volumes that is to be attached and the `data_volume_size` to the size (in GB) for each volume.
```
master                      = {instance_type    = "<master-compute-template>", image_id    = "<image-uuid-rhcos>", "count"   = 3, data_volume_count  = 0, data_volume_size  = 100}
worker                      = {instance_type    = "<worker-compute-template>", image_id    = "<image-uuid-rhcos>", "count"   = 2, data_volume_count  = 0, data_volume_size  = 100}
```
These set of variables specify the username and the SSH key to be used for accessing the bastion node.
```
rhel_username               = "root"  #Set it to an appropriate username for non-root user access
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
```
rhel_username is set to root. rhel_username can be set to an appropriate username having superuser privileges with no password prompt.
Please note that only OpenSSH formatted keys are supported. Refer to the following links for instructions on creating SSH key based on your platform.
- Windows 10 - https://phoenixnap.com/kb/generate-ssh-key-windows-10
- Mac OSX - https://www.techrepublic.com/article/how-to-generate-ssh-keys-on-macos-mojave/
- Linux - https://www.siteground.com/kb/generate_ssh_key_in_linux/

Create the SSH key-pair and keep it under the `data` directory

These set of variables specify the RHEL subscription details, RHEL subscription supports two methods: one is using username and password, the other is using activation key.
This is sensitive data, and if you don't want to save it on disk, use environment variables `RHEL_SUBS_USERNAME` and `RHEL_SUBS_PASSWORD` and pass them to `terraform apply` command as shown in the [Quickstart guide](./quickstart.md#setup-terraform-variables).

```
rhel_subscription_username  = "user@test.com"
rhel_subscription_password  = "mypassword"
```
Or define following variables to use activation key for RHEL subscription:
```
rhel_subscription_org = "org-id"
rhel_subscription_activationkey = "activation-key"
```
### OpenShift Installation Details

These variables specify the URL for the OpenShift installer and client binaries.
Change the URL to the specific stable or pre-release version that you want to install on PowerVS.
Reference link - `https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/`

For latest stable:
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable/openshift-client-linux.tar.gz"
```
For specific stable version:
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.11/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.11/openshift-client-linux.tar.gz"
```
For pre-release:
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp-dev-preview/latest/openshift-client-linux.tar.gz"
```

This variable specifies the OpenShift pull secret. This is available from the following link -  https://cloud.redhat.com/openshift/install/power/user-provisioned
Download the secret and copy it to `data/pull-secret.txt`.
```
pull_secret_file            = "data/pull-secret.txt"
```

These variables specifies the OpenShift cluster domain details.
Edit it as per your requirements.
```
cluster_domain              = "ibm.com"
cluster_id_prefix           = "test-ocp"
cluster_id                  = ""
```
Set the `cluster_domain` to `nip.io`, `xip.io` or `sslip.io` if you prefer using online wildcard domains.
Default is `ibm.com`.
The `cluster_id_prefix` should not be more than 8 characters. Nodes are pre-fixed with this value.
Default value is `test-ocp`
If `cluster_if_prefix` is not set, the `cluster_id` will be used only without prefix.

A random value will be used for `cluster_id` if not set.
The total length of `cluster_id_prefix`.`cluster_id` should not exceed 14 characters.

### FIPS Variable for OpenShift deployment

These variables will be used for deploying OCP in FIPS mode.
Change the values as per your requirement.
```
fips_compliant      = false
```

### Misc Customizations

These variables provides miscellaneous customizations. For common usage scenarios these are not required and should be left unchanged.

The following variables are used to define the IP address for the preconfigured external DNS and the Load-balancer.
```
lb_ipaddr                       = ""
ext_dns                         = ""
```

The following variable is used to set the network adapter type for the VMs. By default the VMs will use SEA. If SRIOV is required then uncomment the variable
```
network_type                = "SRIOV"
```

The following variable is used to define the amount of SR-IOV Virtual Functions used for VNIC failover of the network adapter for the VMs. By default the VMs will use 1, which defines `no VNIC failover`. Any setting higher then 1 creates additional virtual functions and configures them in a VNIC failover setup. `Be aware of the fact, that RHCOS and some Linux releases might not handle VNIC failover with more then 2 SR-IOV Virtual Functions properly. The recommended value is 2 for VNIC failover.`
Valid options are: Any number supported for VNIC failover from 1 to 6
```
sriov_vnic_failover_vfs                = 1
```

The following variable is used to define the capacity of SR-IOV Logical Ports of the 1st network adapter for the VMs. By default the VMs will use 2%.
Valid options are: Any number which can be devided by 2 and results in an integer. 100% = 1.0; 80% = 0.80; 60% = 0.60; etc
```
sriov_capacity                = 0.02
```

The following variable is used to specify the PowerVC [Storage Connectivity Group](https://www.ibm.com/support/knowledgecenter/SSVSPA_1.4.4/com.ibm.powervc.cloud.help.doc/powervc_storage_connectivity_groups_cloud.html) (SCG). Empty value will use the default SCG
```
scg_id                      = ""
```

The following variables can be used for disconnected install by using a local mirror registry on the bastion node.

```
enable_local_registry      = false  #Set to true to enable usage of local registry for restricted network install.
local_registry_image       = "docker.io/ibmcom/registry-ppc64le:2.6.2.5"
ocp_release_tag            = "4.4.9-ppc64le"
ocp_release_name           = "ocp-release"
```

This variable can be used for trying out custom OpenShift install image for development use.
```
release_image_override     = ""
```

These variables specify the ansible playbooks that are used for OpenShift install and post-install customizations.
```
helpernode_repo            = "https://github.com/RedHatOfficial/ocp4-helpernode"
helpernode_tag             = "bf7842ec240f1d9ba5b5f9897bb72e7c86500faa"
install_playbook_repo      = "https://github.com/ocp-power-automation/ocp4-playbooks"
install_playbook_tag       = "main"
```

This variable specify the MTU value for the private network interface on RHEL and RHCOS nodes. The CNI network will have <private_network_mtu> - 50 for OpenshiftSDN and <private_network_mtu> - 100 for OVNKubernetes network provider.
```
private_network_mtu         = 1450
```

These variables can be used when debugging ansible playbooks
```
installer_log_level         = "info"
ansible_extra_options       = "-v"
```

This variable specifies the external DNS servers to forward DNS queries that cannot be resolved locally.
```
dns_forwarders              = "1.1.1.1; 9.9.9.9"
```

List of [day-1 kernel arguments](https://docs.openshift.com/container-platform/latest/installing/install_config/installing-customizing.html#installation-special-config-kargs_installing-customizing) for the cluster nodes.
To add kernel arguments to master or worker nodes, using MachineConfig object and inject that object into the set of manifest files used by Ignition during cluster setup.
```
rhcos_pre_kernel_options        = []
```
- Example 1
  ```
  rhcos_pre_kernel_options   = ["rd.multipath=default","root=/dev/disk/by-label/dm-mpath-root"]
  ```

List of [kernel arguments](https://docs.openshift.com/container-platform/4.4/nodes/nodes/nodes-nodes-working.html#nodes-nodes-kernel-arguments_nodes-nodes-working) for the cluster nodes.
Note that this will be applied after the cluster is installed and all the nodes are in `Ready` status.
```
rhcos_kernel_options        = []
```
- Example 1
  ```
  rhcos_kernel_options      = ["slub_max_order=0","loglevel=7"]
  ```

These are NTP specific variables that are used for time-synchronization in the OpenShift cluster.
```
chrony_config               = true
chrony_config_servers       = [ {server = "0.centos.pool.ntp.org", options = "iburst"}, {server = "1.centos.pool.ntp.org", options = "iburst"} ]
```

These set of variables are specific for cluster wide proxy configuration.
Public internet access for the OpenShift cluster nodes is via Squid proxy deployed on the bastion.
```
setup_squid_proxy           = false
```

If you have a separate proxy, and don't want to set the Squid proxy on bastion then use the following variables.
```
setup_squid_proxy           = false
proxy                       = {server = "hostname_or_ip", port = "3128", user = "pxuser", password = "pxpassword"}
```
Except `server` all other attributes are optional. Default `port` is `3128` with unauthenticated access.


The following variable allows using RAM disk for etcd. This is not meant for production use cases
```
mount_etcd_ramdisk          = false
```

These variables specify details about NFS storage that is setup by default on the bastion server.

```
storage_type                = "nfs"
volume_size                 = "300" # Value in GB
volume_storage_template     = ""
```

The following variables are specific to upgrading an existing installation.

```
upgrade_version            = ""
upgrade_channel            = ""  #(stable-4.x, fast-4.x, candidate-4.x) eg. stable-4.11
upgrade_image              = ""  #(e.g. `"quay.io/openshift-release-dev/ocp-release-nightly@sha256:xxxxx"`)
upgrade_pause_time         = "90"
upgrade_delay_time         = "600"
```

The following variables are specific to performing EUS upgrades.

```
eus_upgrade_version        = "4.11.14"
eus_upgrade_channel        = "stable-4.11"  #(stable-4.x, fast-4.x, candidate-4.x, eus-4.x)
eus_upgrade_image          = "quay.io/openshift-release-dev/ocp-release:4.11.14-ppc64le"
eus_upstream               = "" (e.g. `"https://ppc64le.ocp.releases.ci.openshift.org/graph"`)
```


This variable is used to set the default Container Network Interface (CNI) network provider such as OpenShiftSDN or OVNKubernetes

```
cni_network_provider       = "OVNKubernetes"
cluster_network_cidr        = "10.128.0.0/14"
cluster_network_hostprefix  = "23"
service_network             = "172.30.0.0/16"
```

These set of variables are specific for LUKS encryption configuration and installation.

```
luks_compliant               = false # Set it true if you prefer to use FIPS enable in ocp deployment
luks_config                  = [ { thumbprint = "", url = "" }, { thumbprint = "", url = "" }, { thumbprint = "", url = "" } ]
luks_filesystem_device       = "/dev/mapper/root"  #Set this value for file system device
luks_format                  = "xfs"  #Set value of format for filesystem
luks_wipe_filesystem         = true  #Configures the FileSystem to be wiped
luks_device                  = "/dev/disk/by-partlabel/root"  #Set value of luks device
luks_label                   = "luks-root"  #Set value of tang label
luks_options                 = ["--cipher", "aes-cbc-essiv:sha256"]  #Set List of luks options for the luks encryption
luks_wipe_volume             = true  #Configures the luks encrypted partition to be wiped
luks_name                    = "root"  #Set value of luks name
```
