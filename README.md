# Terraform for OpenShift 4.X on PowerVM/PowerVC
This repo contains Terraform templates required to deploy OCP 4.3 on PowerVM LPARs managed via IBM PowerVC. Terraform resources are implemented by refering to https://github.com/openshift/installer/blob/release-4.3/docs/user/openstack/install_upi.md.

This module will not setup a private network for running the cluster. Instead, it will create the nodes on same network as provided in the inputs. Initially network ports are created for 1 bootstrap, N masters and M workers nodes. This is required for setting up a DHCP server for nodes to pick up the port IPs. This module also setup a DNS server and HAPROXY server on the bastion node.

Run this code from either Mac or Linux (Intel) system.

:heavy_exclamation_mark: *This automation is intended for test/development purposes only and there is no formal support. For issues please open a GitHub issue*

## How-to install Terraform
https://learn.hashicorp.com/terraform/getting-started/install.html

Please follow above link to download and install Terraform on your machine. Here is the download page for your convenience https://www.terraform.io/downloads.html. Ensure you are using Terraform 0.12.20 and above. These modules are tested with the given(latest at this moment) version.

## Image and LPAR requirements

You'll need to create CoreOS image in PowerVC. Follow the steps mentioned [here](./coreos-image-creation.md).
Following are the recommended LPAR configs for OpenShift nodes
- Bootstrap, Master - 2 vCPUs, 16GB RAM, 120 GB Disk

   **_This config is suitable for majority of the scenarios_**
- Worker - 2 vCPUs, 16GB RAM, 120 GB Disk

   **_Increase worker vCPUs, RAM and Disk based on application requirements_**

## Setup this repo
On your Terraform client machine:
1. Clone this repo
2. `cd ocp4_upi_powervm`

## How-to set Terraform variables
Edit the var.tfvars file with following values:
 * `auth_url` : Endpoint URL used to connect to PowerVC.
 * `user_name` : PowerVC login username.
 * `password` :  PowerVC login password.
 * `tenant_name` :  The Name of the Tenant (Identity v2) or Project (Identity v3) to login with.
 * `domain_name` : The Name of the Domain to scope to.
 * `openstack_availability_zone` : The availability zone in which to create the servers.
 * `network_name` : Name of the network to use for deploying all the hosts.
 * `network_type` (Optional) : Type of the network adapter for cluster hosts. You can set the value as "SRIOV", any other value will use "SEA". More info [here](https://www.ibm.com/support/knowledgecenter/SSXK2N_1.4.0/com.ibm.powervc.standard.help.doc/powervc_sriov_overview.html).
 * `scg_id` : ID of the PowerVC [Storage Connectivity Group](https://www.ibm.com/support/knowledgecenter/SSVSPA_1.4.4/com.ibm.powervc.cloud.help.doc/powervc_storage_connectivity_groups_cloud.html) (SCG) to use for all nodes. Empty value will use the default SCG. Deployments might fail if you don't provide this value and have more than one default SCG configured on PowerVC.
 * `rhel_username` : The user that we should use for the connection to the bastion host.
 * `keypair_name` : Optional value for keypair used. Default is <cluster_id>-keypair.
 * `public_key_file` : A pregenerated OpenSSH-formatted public key file. Default path is 'data/id_rsa.pub'.
 * `private_key_file` : Corresponding private key file. Default path is 'data/id_rsa'.
 * `private_key` : The contents of an SSH key to use for the connection. Ignored if `public_key_file` is provided.
 * `public_key` : The contents of corresponding key to use for the connection. Ignored if `public_key_file` is provided.
 * `rhel_subscription_username` : The username required for RHEL subcription on bastion host.
 * `rhel_subscription_password` : The password required for RHEL subcription on bastion host.
 * `bastion` : Map of below parameters for bastion host.
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the desired RHEL image.
 * `bootstrap` : Map of below parameters for bootstrap host.
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the desired CoreOS image.
    * `count` : Always set the value to 1 before starting the deployment. When the deployment is completed successfully set to 0 to delete the bootstrap node.
 * `master` : Map of below parameters for master hosts.
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the desired CoreOS image.
    * `count` : Number of master nodes.
 * `worker` : Map of below parameters for worker hosts. (Atleaset 2 Workers are required for running router pods)
    * `instance_type` : The name of the desired flavor.
    * `image_id` : The image ID of the desired CoreOS image.
    * `count` : Number of worker nodes.
 * `openshift_install_tarball` : HTTP URL for openhift-install tarball.
 * `release_image_override` : This is set to OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE while creating ign files. If you are using internal artifactory then ensure that you have added auth key to pull-secret.txt file.
 * `pull_secret_file` : Location of the pull-secret file to be used.
 * `cluster_domain` : Cluster domain name. cluster_id.cluster_domain together form the fully qualified domain name.
 * `dns_enabled` : Flag for installing and configuring DNS server on bastion node. Any value other than "true" will delete the DNS configurations.
 * `cluster_id_prefix` : Cluster identifier. Should not be more than 8 characters. Nodes are pre-fixed with this value, please keep it unique (may be with your name).
 * `storage_type` : Storage provisioner to configure. Supported values: nfs (For now only nfs provisioner is supported, any other value won't setup a storageclass)
 * `storageclass_name` : StorageClass name to be given.
 * `volume_size` : If storage_type is nfs, a volume will be created with given size in GB and attached to bastion node. Eg: 1000 for 1TB disk.
 * `volume_storage_template` : Storage template name or ID for creating the volume. Empty value will use default template.

## How-to set required data files
You need to have following files in data/ directory before running the Terraform templates.
```
# ls data/
id_rsa  id_rsa.pub  pull-secret.txt
```
 * `id_rsa` & `id_rsa.pub` : The key pair used for accessing the hosts. These files are not required if you provide `public_key_file` and `private_key_file`.
 * `pull-secret.txt` : File containing keys required to pull images on the cluster. You can download it from RH portal after login https://cloud.redhat.com/openshift/install/pull-secret.

## How-to run Terraform resources
On your Terraform client machine & tf_openshift4_pvc directory:
1. `terraform init`
2. `terraform apply -var-file var.tfvars`

Now wait for the installation to complete. It may take around 40 mins to complete provisioning.

**IMPORTANT**: Once the deployment is completed successfully, you can safely delete the bootstrap node. After this, the HAPROXY server will not point to the APIs from bootstrap node once the cluster is up and running. Clients will start consuming APIs from master nodes once the bootstrap node is deleted. Take backup of all the required files from bootstrap node (eg: logs) before running below steps.

To delete the bootstrap node:
1. Change the `count` value to 0 in `bootstrap` map variable and re-run the apply command. Eg: `bootstrap = {instance_type = "medium", image_id = "468863e6-4b33-4e8b-b2c5-c9ef9e6eedf4", "count" = 0}`
2. Run command `terraform apply -var-file var.tfvars`


## Create API and Ingress DNS Records
You will also need to add the following records to your DNS:
```
api.<cluster name>.<base domain>.  IN  A  <Bastion IP>
*.apps.<cluster name>.<base domain>.  IN  A  <Bastion IP>
```
If you're unable to create and publish these DNS records, you can add them to your /etc/hosts file.
```
<Bastion IP> api.<cluster name>.<base domain>
<Bastion IP> console-openshift-console.apps.<cluster name>.<base domain>
<Bastion IP> integrated-oauth-server-openshift-authentication.apps.<cluster name>.<base domain>
<Bastion IP> oauth-openshift.apps.<cluster name>.<base domain>
<Bastion IP> prometheus-k8s-openshift-monitoring.apps.<cluster name>.<base domain>
<Bastion IP> grafana-openshift-monitoring.apps.<cluster name>.<base domain>
<Bastion IP> <app name>.apps.<cluster name>.<base domain>
```

Hint: For your convenience entries specific to your cluster will be printed at the end of a successful run. Just copy and paste value of output variable `etc_hosts_entries` to your hosts file.

## OCP login credentials for CLI and GUI
The OCP login credentials are in bastion host. In order to retrieve the same follow these steps:
1. `ssh -i data/id_rsa root@<bastion_ip>`
2. `cd ~/openstack-upi/auth`
3. `kubeconfig` can be used for CLI (`oc` or `kubectl`)
4. `kubeadmin` user and content of `kubeadmin-pasword` as password for GUI


## Cleaning up
Run `terraform destroy -var-file var.tfvars` to make sure that all resources are properly cleaned up. Do not manually clean up your environment unless both of the following are true:

1. You know what you are doing
2. Something went wrong with an automated deletion.
