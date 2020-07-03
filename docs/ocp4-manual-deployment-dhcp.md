## **Create Master/Worker/Bootstrap Nodes**

Create the below PowerVM LPARS with empty disk volume attached (refer the documentation [link](https://docs.openshift.com/container-platform/4.3/installing/installing_ibm_power/installing-ibm-power.html#minimum-resource-requirements_installing-ibm-power) for resource requirements) and note the MAC ID for each of the LPARs.

- bootstrap - 1
- master  - 3
- worker - 2

## **Create and Setup Bastion Node**

- Create RHEL 8.1 LPAR
- Login to the RHEL 8.1 LPAR and clone the OCP4 [helpernode](https://github.com/RedHatOfficial/ocp4-helpernode) repo
- Use the following vars.yaml as a template and change the IP, network and related details according to your environment.
```
---
disk: sda
helper:
  name: "helper"
  ipaddr: "192.168.7.77"
dns:
  domain: "example.com"
  clusterid: "ocp4"
  forwarder1: "8.8.8.8"
  forwarder2: "8.8.4.4"
dhcp:
  router: "192.168.7.1"
  bcast: "192.168.7.255"
  netmask: "255.255.255.0"
  poolstart: "192.168.7.10"
  poolend: "192.168.7.30"
  ipid: "192.168.7.0"
  netmaskid: "255.255.255.0"
bootstrap:
  name: "bootstrap"
  ipaddr: "192.168.7.20"
  macaddr: "52:54:00:60:72:67"
masters:
  - name: "master0"
    ipaddr: "192.168.7.21"
    macaddr: "52:54:00:e7:9d:67"
  - name: "master1"
    ipaddr: "192.168.7.22"
    macaddr: "52:54:00:80:16:23"
  - name: "master2"
    ipaddr: "192.168.7.23"
    macaddr: "52:54:00:d5:1c:39"
workers:
  - name: "worker0"
    ipaddr: "192.168.7.11"
    macaddr: "52:54:00:f4:26:a1"
  - name: "worker1"
    ipaddr: "192.168.7.12"
    macaddr: "52:54:00:82:90:00"

ppc64le: true
ocp_bios: "https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.4/latest/rhcos-4.4.9-ppc64le-metal.ppc64le.raw.gz"
ocp_initramfs: "https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.4/latest/rhcos-4.4.9-ppc64le-installer-initramfs.ppc64le.img"
ocp_install_kernel: "https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.4/latest/rhcos-4.4.9-ppc64le-installer-kernel-ppc64le"
ocp_client: "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.4/openshift-client-linux.tar.gz"
ocp_installer: "https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/stable-4.4/openshift-install-linux.tar.gz"
```
- Run the playbook
```
ansible-playbook -e @vars.yaml tasks/main.yml
```

- Create ignition configs
```
mkdir ~/ocp4
cd ~/ocp4
```

Create a place to store your pull-secret
```
mkdir -p ~/.openshift
```
Visit try.openshift.com and select "Bare Metal". Download your pull secret and save it under ~/.openshift/pull-secret
```
# ls -1 ~/.openshift/pull-secret
/root/.openshift/pull-secret
```
This playbook creates an ssh key for you; it's under `~/.ssh/helper_rsa`. You can use this key or create/user another one if you wish.
```
# ls -1 ~/.ssh/helper_rsa
/root/.ssh/helper_rsa
```
**Note** - If you want you use your own ssh key, please modify `~/.ssh/config` to reference your key instead of the one deployed by the playbook

Next, create an `install-config.yaml` file.

**Note** - Make sure you update if your filenames or paths are different.
```
cat <<EOF > install-config.yaml
apiVersion: v1
baseDomain: example.com
compute:
- hyperthreading: Enabled
  name: worker
  replicas: 0
controlPlane:
  hyperthreading: Enabled
  name: master
  replicas: 3
metadata:
  name: ocp4
networking:
  clusterNetworks:
  - cidr: 10.254.0.0/16
    hostPrefix: 24
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
pullSecret: '$(< ~/.openshift/pull-secret)'
sshKey: '$(< ~/.ssh/helper_rsa.pub)'
EOF
```
Create the installation manifests
```
openshift-install create manifests
```
Edit the `manifests/cluster-scheduler-02-config.yml` Kubernetes manifest file to prevent Pods from being scheduled on the control plane machines by setting `mastersSchedulable` to `false`.
```
$ sed -i 's/mastersSchedulable: true/mastersSchedulable: false/g' manifests/cluster-scheduler-02-config.yml
```
It should look something like this after you edit it.
```
$ cat manifests/cluster-scheduler-02-config.yml
apiVersion: config.openshift.io/v1
kind: Scheduler
metadata:
  creationTimestamp: null
  name: cluster
spec:
  mastersSchedulable: false
  policy:
    name: ""
status: {}
```
Next, generate the ignition configs
```
openshift-install create ignition-configs
```
Finally, copy the ignition files in the ignition directory for the websever
```
cp ~/ocp4/*.ign /var/www/html/ignition/
restorecon -vR /var/www/html/
chmod o+r /var/www/html/ignition/*.ign
```

## **Boot the LPARs**
Boot the LPARs in the following order and ensure the LPARs perform DHCP boot

1. Bootstrap
2. Masters
3. Workers

## **Wait for Install**

```
openshift-install wait-for bootstrap-complete --log-level debug
```

## **Finish Install**
First, login to your cluster
```
export KUBECONFIG=/root/ocp4/auth/kubeconfig
```
Your install may be waiting for worker nodes to get approved.
Normally it's automated. However, sometimes this needs to be done manually. Check pending CSRs with the following command.
```
oc get csr
```
You can approve all pending CSRs in "one shot" with the following command
```
oc get csr -o go-template='{{range .items}}{{if not .status}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' | xargs oc adm certificate approve
```

You may have to run the command multiple times depending on how many workers you have and in what order they come in. Keep a watch on the CSRs by running the following command
```
watch oc get csr
```

Set the registry for your cluster

First, you have to set the `managementState` to `Managed` for your cluster
```
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"managementState":"Managed"}}'
```
For PoCs, using emptyDir is ok (to use PVs follow this doc)
```
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"storage":{"emptyDir":{}}}}'
```
If you need to expose the registry, run this command
```
oc patch configs.imageregistry.operator.openshift.io/cluster --type merge -p '{"spec":{"defaultRoute":true}}'
```
**Note** - You can watch the operators running with ```oc get clusteroperators```


## **Login to the web console**
The OpenShift 4 web console will be running at `https://console-openshift-console.apps.{{ dns.clusterid }}.{{ dns.domain }} (e.g. https://console-openshift-console.apps.ocp4.example.com)`

- Username: kubeadmin
- Password: the output of `cat /root/ocp4/auth/kubeadmin-password`

**Note** - You'll need to update your `/etc/hosts` settings if using private dhcp server running on the bastion node

References:
- [Quickstart Guide](https://github.com/RedHatOfficial/ocp4-helpernode/blob/master/docs/quickstart.md)
- [Power QuickStart Guide](https://github.com/RedHatOfficial/ocp4-helpernode/blob/master/docs/quickstart-ppc64le.md)

