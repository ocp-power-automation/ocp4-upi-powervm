# Installation Quickstart

- [Setup Repository](#setup-repository)
- [Setup Variables](#setup-variables)
- [Setup Data Files](#setup-data-files)
- [Start Install](#start-install)
- [Post Install](#post-install)
- [Cluster Access](#cluster-access)
- [Clean up](#clean-up)


## Setup Repository

Clone this git repository on the client machine:
```
git clone https://github.com/ocp-power-automation/ocp4-upi-powervm.git
cd ocp4_upi_powervm
```

## Setup Variables.

Update the var.tfvars with values explained in the following sections. You can also set the variables using other ways mentioned [here](https://www.terraform.io/docs/configuration/variables.html#assigning-values-to-root-module-variables) such as -var option or environment variables.

### Setup PowerVC Environment Variables

Update the following variables specific to your environment.

 * `auth_url` : (Required) Endpoint URL used to connect to PowerVC.
 * `user_name` : (Required) PowerVC login username.
 * `password` : (Required) PowerVC login password.
 * `tenant_name` : (Required) The Name of the Tenant (Identity v2) or Project (Identity v3) to login with.
 * `network_name` : (Required) Name of the network to use for deploying all the hosts.
 * `domain_name` : (Optional) The Name of the Domain to scope to. If not specified the value is set to "Default".
 * `openstack_availability_zone` : (Optional) The availability zone in which to create the servers. Keep blank for the default availability zone.
 * `network_type`   : (Optional) Type of the network adapter for cluster hosts. You can set the value as "SRIOV", any other value will use "SEA". More info [here](https://www.ibm.com/support/knowledgecenter/SSXK2N_1.4.0/com.ibm.powervc.standard.help.doc/powervc_sriov_overview.html).
 * `scg_id`         : (Optional) ID of the PowerVC [Storage Connectivity Group](https://www.ibm.com/support/knowledgecenter/SSVSPA_1.4.4/com.ibm.powervc.cloud.help.doc/powervc_storage_connectivity_groups_cloud.html) (SCG) to use for all nodes. An empty value will use the default SCG. Deployments might fail if you don't provide this value when having more than one default SCG configured on PowerVC.

### Setup Nodes Variables

Update the following variables specific to your cluster requirement. All the variables are required to be specified.

 * `bastion` : Map of below parameters for bastion host.
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the RHEL 8.1 image.
 * `bootstrap` : Map of below parameters for bootstrap host.
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the RHCOS image.
    * `count` : Always set the value to 1 before starting the deployment. When the deployment is completed successfully set to 0 to delete the bootstrap node.
 * `master` : Map of below parameters for master hosts.
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the desired RHCOS image.
    * `count` : Number of master nodes.
 * `worker` : Map of below parameters for worker hosts. (Atleaset 2 Workers are required for running router pods in HA mode)
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the desired RHCOS image.
    * `count` : Number of worker nodes.

### Setup Intrumentation Variables

Update the following variables specific to the nodes.

 * `rhel_subscription_username` : (Required) The username required for RHEL subscription on bastion host.
 * `rhel_subscription_password` : (Required) The password required for RHEL subscription on bastion host.
 * `rhel_username` : (Optional) The user that we should use for the connection to the bastion host. The default value is set as "root user.
 * `keypair_name` : (Optional) Value for keypair used. Default is <cluster_id>-keypair.
 * `public_key_file` : (Optional) A pregenerated OpenSSH-formatted public key file. Default path is 'data/id_rsa.pub'.
 * `private_key_file` : (Optional) Corresponding private key file. Default path is 'data/id_rsa'.
 * `private_key` : (Optional) The contents of an SSH key to use for the connection. Ignored if `public_key_file` is provided.
 * `public_key` : (Optional) The contents of corresponding key to use for the connection. Ignored if `public_key_file` is provided.

### Setup OpenShift Variables

Update the following variables specific to OCP.

 * `openshift_install_tarball` : (Required) HTTP URL for OpenShift install tarball.
 * `openshift_client_tarball` : (Required) HTTP URL for OpenShift client (`oc`) tarball.
 * `cluster_domain` : (Required) Cluster domain name. `<cluster_id>.<cluster_domain>` forms the fully qualified domain name.
 * `cluster_id_prefix` : (Required) Cluster identifier. Should not be more than 8 characters. Nodes are pre-fixed with this value, please keep it unique.
 * `release_image_override` : (Optional) This is set to OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE while creating ignition files. Not applicable when using local registry setup.

### Setup Additonal OpenShift Variables

 * `installer_log_level` : (Optional) Log level for OpenShift install (e.g. "debug | info | warn | error") (default "info")
 * `ansible_extra_options` : (Optional) Ansible options to append to the ansible-playbook commands. Default is set to "-v".
 * `helpernode_tag` : (Optional) [ocp4-helpernode](https://github.com/RedHatOfficial/ocp4-helpernode) ansible playbook version to checkout.
 * `install_playbook_tag` : (Optional) [ocp4-playbooks](https://github.com/ocp-power-automation/ocp4-playbooks) ansible playbooks version to checkout.
 * `pull_secret_file` : (Optional) Location of the OCP pull-secret file to be used. Default path is 'data/pull-secret.txt'.
 * `dns_forwarders` : (Optional) External DNS servers to forward DNS queries that cannot resolve locally. Eg: `"8.8.8.8; 9.9.9.9"`.
 * `mount_etcd_ramdisk` : (Optional) Flag for mounting etcd directory in the ramdisk. Note that the data will not be persistent.
 * `rhcos_kernel_options` : (Optional) List of [kernel arguments](https://docs.openshift.com/container-platform/4.4/nodes/nodes/nodes-nodes-working.html#nodes-nodes-kernel-arguments_nodes-nodes-working) for the cluster nodes eg: ["slub_max_order=0","loglevel=7"]. Note that this will be applied after the cluster is installed, hence wait till all the nodes are in `Ready` status before you start using the cluster. Check nodes status using the command `oc get nodes`.
 * `sysctl_tuned_options` : (Optional) Set to true to apply sysctl options via tuned operator. For more information check [Using the Node Tuning Operator](https://docs.openshift.com/container-platform/4.3/scalability_and_performance/using-node-tuning-operator.html) & [Using the Red Hat OpenShift Node Tuning Operator to set kernel parameters](https://www.ibm.com/support/producthub/icpdata/docs/content/SSQNUZ_current/cpd/svc/dbs/db2wh-nodetuningop.html)
 * `sysctl_options` : (Required when `sysctl_tuned_options = true`) List of sysctl options to apply.
 * `match_array` : (Required when `sysctl_tuned_options = true`) Multi-line config with node/pod selection criteria. Set of supported keys for each criteria: label, value & type.
 * `proxy` : (Optional) Map of below parameters for using a proxy server to setup OCP on a private network.
    * `server` : Proxy server hostname or IP.
    * `port` : Proxy port to use (default is 3128).
    * `user` : Proxy server user for authentication.
    * `password` : Proxy server password for authentication.

### Setup Storage Variables

Update the following variables specific to OCP storage. Note that currently only NFS storage provisioner is supported.

 * `storage_type` : (Optional) Storage provisioner to configure. Supported values: nfs (For now only nfs provisioner is supported, any other value won't setup a storageclass)
 * `volume_size` : (Optional) If storage_type is nfs, a volume will be created with given size (default 300) in GB and attached to bastion node. Eg: 1000 for 1TB disk.
 * `volume_storage_template` : (Optional) Storage template name or ID for creating the volume. Empty value will use default template.
 
### Setup Local Registry Variables

Update the following variables specific to OCP local registry. Note that this is required only for restricted network install.

 * `enable_local_registry` : (Optional) Set to true to enable usage of local registry for restricted network install.
 * `local_registry_image` : (Optional) This is the name of the image used for creating the local registry container.
 * `ocp_release_tag` : (Optional) The version of OpenShift you want to sync. Determine the tag by referring the [Repository Tags](https://quay.io/repository/openshift-release-dev/ocp-release?tab=tags) page.

### Setup OCP Upgrade Variables

Update the following variables specific to OCP upgrade. The upgrade will be performed after a successful install of OCP.

 * `upgrade_image` : (Optional) OpenShift release image having higher and supported version. If set, OCP cluster will be upgraded to this image version. (e.g. `"quay.io/openshift-release-dev/ocp-release-nightly@sha256:552ed19a988fff336712a50..."`)
 * `upgrade_pause_time` : (Optional) Minutes to pause the playbook execution before starting to check the upgrade status once the upgrade command is executed.
 * `upgrade_delay_time` : (Optional) Seconds to wait before re-checking the upgrade status once the playbook execution resumes.


## Setup Data Files

You need to have the following files in data/ directory before running the Terraform templates.
```
$ ls data/
id_rsa  id_rsa.pub  pull-secret.txt
```
 * `id_rsa` & `id_rsa.pub` : The key pair used for accessing the hosts. These files are not required if you provide `public_key_file` and `private_key_file`.
 * `pull-secret.txt` : File containing keys required to pull images on the cluster. You can download it from RH portal after login https://cloud.redhat.com/openshift/install/pull-secret.


## Start Install

Run the following commands from where you have cloned this repository:

```
terraform init
terraform apply -var-file var.tfvars
```

Now wait for the installation to complete. It may take around 40 mins to complete provisioning.

**IMPORTANT**: When using NFS storage, the OpenShift image registry will be using NFS PV claim. Otherwise the image registry uses ephemeral PV.


## Post Install

### Delete Bootstrap Node

Once the deployment is completed successfully, you can safely delete the bootstrap node. This step is optional but recommended to free up the used during install.

1. Change the `count` value to 0 in `bootstrap` map variable and re-run the apply command. Eg: `bootstrap = {instance_type = "medium", image_id = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4", "count" = 0}`
2. Run command `terraform apply -var-file var.tfvars`


### Create API and Ingress DNS Records
You will also need to add the following records to your DNS server:
```
api.<cluster name>.<cluster domain>.  IN  A  <Bastion IP>
*.apps.<cluster name>.<cluster domain>.  IN  A  <Bastion IP>
```

If you're unable to create and publish these DNS records, you can add them to your `hosts` file. For Linux and Mac `hosts` file is located at /etc/hosts and for Windows it can be found at c:\Windows\System32\Drivers\etc\hosts.
```
<Bastion IP> api.<cluster name>.<cluster domain>
<Bastion IP> console-openshift-console.apps.<cluster name>.<cluster domain>
<Bastion IP> integrated-oauth-server-openshift-authentication.apps.<cluster name>.<cluster domain>
<Bastion IP> oauth-openshift.apps.<cluster name>.<cluster domain>
<Bastion IP> prometheus-k8s-openshift-monitoring.apps.<cluster name>.<cluster domain>
<Bastion IP> grafana-openshift-monitoring.apps.<cluster name>.<cluster domain>
<Bastion IP> <app name>.apps.<cluster name>.<cluster domain>
```

**Note**: For convenience, entries specific to your cluster will be printed at the end of a successful run. Just copy and paste value of output variable `etc_hosts_entries` to your hosts file.


## Cluster Access

The OCP login credentials are in bastion host. To retrieve the same follow these steps:
1. `ssh -i data/id_rsa <rhel_username>@<bastion_ip>`
2. `cd ~/openstack-upi/auth`
3. `kubeconfig` can be used for CLI (`oc` or `kubectl`)
4. `kubeadmin` user and content of `kubeadmin-password` as password for GUI


The OpenShift web console URL will be printed with output variable `web_console_url` (eg. https://console-openshift-console.apps.test-ocp-090e.rhocp.com) on successful run. Open this URL on your browser and login with user `kubeadmin` and password as retrieved above.

The OpenShift command-line client is already configured on the bastion node with kubeconfig placed at `~/.kube/config`. Just start using the oc client directly.


## Clean up

To destroy after you are done using the cluster you can run command `terraform destroy -var-file var.tfvars` to make sure that all resources are properly cleaned up.
Do not manually clean up your environment unless both of the following are true:

1. You know what you are doing
2. Something went wrong with an automated deletion.
