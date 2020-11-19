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
bastion                     = {instance_type    = "<bastion-compute-template>", image_id    = "<image-uuid-rhel>"}
bootstrap                   = {instance_type    = "<bootstrap-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 1}
master                      = {instance_type    = "<master-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 3}
worker                      = {instance_type    = "<worker-compute-template>", image_id    = "<image-uuid-rhcos>",  "count"   = 2}
```

`instance_type` is the compute template to be used and `image_id` is the image UUID. `count` specifies the number of VMs that should be created for each type.

You can optionally set worker `count` value to 0 in which case all the cluster pods will be running on the master/supervisor nodes.
Ensure you use proper sizing for master/supervisor nodes to avoid resource starvation for containers.

These set of variables specify the username and the SSH key to be used for accessing the bastion node.
```
rhel_username               = "root"
public_key_file             = "data/id_rsa.pub"
private_key_file            = "data/id_rsa"
```
Please note that only OpenSSH formatted keys are supported. Refer to the following links for instructions on creating SSH key based on your platform.
- Windows 10 - https://phoenixnap.com/kb/generate-ssh-key-windows-10
- Mac OSX - https://www.techrepublic.com/article/how-to-generate-ssh-keys-on-macos-mojave/
- Linux - https://www.siteground.com/kb/generate_ssh_key_in_linux/

Create the SSH key-pair and keep it under the `data` directory

These set of variables specify the RHEL subscription details.
This is sensitive data, and if you don't want to save it on disk, use environment variables `RHEL_SUBS_USERNAME` and `RHEL_SUBS_PASSWORD` and
pass them to `terraform apply` command as shown in the [Quickstart guide](./quickstart.md#setup-terraform-variables).

```
rhel_subscription_username  = "user@test.com"
rhel_subscription_password  = "mypassword"
```

### OpenShift Installation Details

These variables specify the URL for the OpenShift installer and client binaries.
Change the URL to the specific 4.6.x version that you want to install
Reference link - `https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp`
```
openshift_install_tarball   = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.6/openshift-install-linux.tar.gz"
openshift_client_tarball    = "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.6/openshift-client-linux.tar.gz"
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

A random value will be used for `cluster_id` if not set.
The total length of `cluster_id_prefix`.`cluster_id` should not exceed 14 characters.

### Misc Customizations

These variables provides miscellaneous customizations. For common usage scenarios these are not required and should be left unchanged.

The following variable is used to set the network adapter type for the VMs. By default the VMs will use SEA. If SRIOV is required then uncomment the variable
```
network_type                = "SRIOV"
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
helpernode_tag             = "5eab3db53976bb16be582f2edc2de02f7510050d"
install_playbook_repo      = "https://github.com/ocp-power-automation/ocp4-playbooks"
install_playbook_tag       = "02a598faa332aa2c3d53e8edd0e840440ff74bd5"
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

List of [kernel arguments](https://docs.openshift.com/container-platform/4.6/nodes/nodes/nodes-nodes-working.html) for the cluster nodes.
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
upgrade_channel            = ""  #(stable-4.x, fast-4.x, candidate-4.x) eg. stable-4.5
upgrade_pause_time         = "90"
upgrade_delay_time         = "600"
```
