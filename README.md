# Terraform for OpenShift 4.X on PowerVC
This repo contains Terraform templates required to deploy OCP 4.3 on VMs running on IBM PowerVC. Terraform resources are implemented by refering to https://github.com/openshift/installer/blob/release-4.3/docs/user/openstack/install_upi.md.

This module with not setup a private network for running the cluster. Instead, it will create the nodes on same network as provided in the inputs. Initially network ports are created for 1 bootstrap, N masters and M workers nodes. This is required for setting up a DHCP server for nodes to pick up the port IPs. This module also setup a DNS server and HAPROXY server on the bastion node.

Run this code from either Mac or Linux (Intel) system.

## How-to install Terraform
https://learn.hashicorp.com/terraform/getting-started/install.html

Please follow above link to download and install Terraform on your machine. Here is the download page for your convenience https://www.terraform.io/downloads.html. Ensure you are using Terraform 0.12.20 and above. These modules are tested with the given(latest at this moment) version.

## Setup this repo
On your Terraform client machine:
1. `git clone git@github.ibm.com:redstack-power/tf_openshift4_pvc.git`
2. `cd tf_openshift4_pvc`
3. `git checkout release-4.3`

## How-to set Terraform variables
Edit the var.tfvars file with following values:
 * auth_url : Endpoint URL used to connect Openstack.
 * user_name : OpenStack username.
 * password :  Openstack password.
 * tenant_name :  The Name of the Tenant (Identity v2) or Project (Identity v3) to login with.
 * domain_name : The Name of the Domain to scope to.
 * openstack_availability_zone : The availability zone in which to create the servers.
 * network_name : An array of one or more networks to attach to the bastion host.
 * rhel_username : The user that we should use for the connection to the bastion host.
 * keypair_name : Optional value for keypair used. Default is <cluster_id>-keypair.
 * public_key_file : A pregenerated OpenSSH-formatted public key file. Default path is 'data/id_rsa.pub'.
 * private_key_file : Corresponding private key file. Default path is 'data/id_rsa'.
 * private_key : The contents of an SSH key to use for the connection. Ignored if public_key_file is provided.
 * public_key : The contents of corresponding key to use for the connection. Ignored if public_key_file is provided.
 * rhel_subscription_username : The username required for RHEL subcription on bastion host.
 * rhel_subscription_password : The password required for RHEL subcription on bastion host.
 * bastion : Map of below parameters for bastion host.
    * instance_type : The name of the desired flavor.
    * image_id : The image ID of the desired RHEL image.
 * bootstrap : Map of below parameters for bootstrap host.
    * instance_type : The name of the desired flavor.
    * image_id : The image ID of the desired CoreOS image
 * master : Map of below parameters for master hosts.
    * instance_type : The name of the desired flavor.
    * image_id : The image ID of the desired CoreOS image
    * count : Number of master nodes.
 * worker : Map of below parameters for worker hosts. (Atleaset 2 Workers are required for running router pods)
    * instance_type : The name of the desired flavor.
    * image_id : The image ID of the desired CoreOS image.
    * count : Number of worker nodes.
 * openshift_install_tarball : HTTP URL for openhift-install tarball.
 * release_image_override : This is set to OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE while creating ign files. If you are using internal artifactory then ensure that you have added auth key to pull-secret.txt file.
 * pull_secret_file : Location of the pull-secret file to be used.
 * cluster_domain : Cluster domain name. cluster_id.cluster_domain together form the fully qualified domain name.
 * cluster_id : Cluster identifier. Should not be more than 14 characters. Nodes are pre-fixed with this value, please keep it unique (may be with your name).

## How-to set required data files
You need to have following files in data/ directory before running the Terraform templates.
```
# ls data/
id_rsa  id_rsa.pub  pull-secret.txt
```
 * id_rsa & id_rsa.pub : The key pair used for accessing the hosts. Note: default user for CoreOS is 'core'.
 * pull-secret.txt : File containing keys required to pull images on the cluster. You can download it from RH portal after login https://cloud.redhat.com/openshift/install/pull-secret.

## How-to run Terraform resources
On your Terraform client machine & tf_openshift4_pvc directory:
1. `terraform init`
2. `terraform apply -var-file var.tfvars`

Now wait for the installation to complete. It may take around 40 mins to complete provisioning.

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

## Cleaning up
Run `terraform destroy -var-file var.tfvars` to make sure that all resources are properly cleaned up. Do not manually clean up your environment unless both of the following are true:

1. You know what you are doing
2. Something went wrong with an automated deletion.
