**1. Create Master/Worker/Bootstrap Nodes**

Create bellow PowerVM LPARS with empty volume attached (Refer the documentation for resourcce requirement) and Note the MAC ID of each VM and also the keep the required number of IPs ready for further configuration.
   
   a. bootstrap - 1
   
   b. master  - 3
   
   c. worker - 3
   
   
**2. Create and Setup Bastion Host**

   A. Create a PowerVM LPAR with sufficient CPU, Memory and Disk space and deploy RHEL8.0 

   B. Enable and start the firewall daomon

   C. Register the bastion VM with RHN and install below set of rpms

   `wget jq git net-tools bind-utils vim python3 httpd tar bind-chroot dhcp-server haproxy`

   D. Enable the respective daemons and reload the daemon for the below services

      a. httpd service - For serving ignition files and disk image
         `systemctl enable httpd ; systemctl start httpd`
      b. named service - For DNS service
         use bellow configuration file for named. Copy the updated configuration files into corresponding location and start the named service
         /etc/named.conf  -  <provide the link to the sample named.conf template>
         /etc/named/zones/cluster-zone.db - <provide the link to sample cluster-zone.db template>
         and 
         `systemctl enable named ; systemctl start named`

   E. Generate ignition files

      a. Download openshift-installer from below location and extract and make available in the PATH
         https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/4.3.18/openshift-install-linux-4.3.18.tar.gz
      b. Create an installation directory
      c. Create `install-config.yaml` in the installation direcoty with content
         <provide the link to the install-config.yaml>
      d. Run `openshift-install create manifests --dir=<installation_directory>`
      e. Update  `manifests/cluster-scheduler-02-config.yml`
         Locate the mastersSchedulable parameter and set its value to False
      f. Run the OpenShift install to generate ignition config files
         `openshift-install create ignition-configs --dir=<installation_directory>`
      g. Update the ignition config files if additional changes are required.

   F. Setup http file server

      a. Make the install-config.yaml and ignition files generated in the httpd Documentroot
         `cp <installation_directory>/install-config.yaml /var/www/html/`
         `cp <installation_directory>/*.ign /var/www/html/`

          where /var/www/html/ is the default Documentroot

      b. Also download `rhcos-4.3.18-ppc64le-metal.ppc64le.raw.gz` from `https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.3/4.3.18/` and make it available in http server by moving it to /var/www/html/

**3. Boot Master, Worker and Bootstrap nodes from RHCOS ISO**

a. Download `rhcos-4.3.18-ppc64le-installer.ppc64le.iso` from `https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.3/4.3.18/`


b. Get the VIOS information where the LPAR got created and copy the rhcos iso into it (Repeat this for each PowerVM LPAR)

```
 Saturday April 11 2020 04:22:17 PM 
╭─~/Downloads                                                                                                                                        ⍉
╰─▶ scp rhcos-4.3.18-ppc64le-installer.ppc64le.iso <vios_user>@<vios_ip>:rhcos.iso
<vios_user>@<vios_ip>'s password:
rhcos-4.3.18-ppc64le-installer.ppc64le.iso            100%   97MB 188.6KB/s   08:45
 Saturday April 11 2020 04:44:02 PM 
╭─~/Downloads
╰─▶
```

Connect to the VIOS and run the below commands to create a virtual optical device out of the iso copied and attach to the LPAR we created.


```
 Saturday April 11 2020 04:22:17 PM 
╭─~/Downloads                                                                                                                                        ⍉
╰─▶ssh <vios_user>@<vios_ip>
<vios_user>@<vios_ip>'s password:
$

$ lsrep
The DVD repository has not been created yet.

$
$
$ mkrep -sp rootvg -size 200M
Virtual Media Repository Created
Repository created within "VMLibrary" logical volume
$
$
$ lsrep
Size(mb) Free(mb) Parent Pool         Parent Size      Parent Free
    1015     1015 rootvg                  1089536          1057792
$
$
$ mkvopt -name rhcos43 -file rhcos.iso
$
$
$ lsrep
Size(mb) Free(mb) Parent Pool         Parent Size      Parent Free
    1015      918 rootvg                  1089536          1057792

Name                                                  File Size Optical         Access
rhcos43                                                      97 None            rw
$

$ mkvdev -fbo -vadapter vhost19
vtopt0 Available
$ lsmap -vadapter vhost19
SVSA            Physloc                                      Client Partition ID
--------------- -------------------------------------------- ------------------
vhost19         U8247.42L.21271DA-V1-C42                     0x00000015

VTD                   vtopt0
Status                Available
LUN                   0x8200000000000000
Backing device        /var/vio/VMLibrary/rhcos43
Physloc
Mirrored              N/A

$
$ lsrep
Size(mb) Free(mb) Parent Pool         Parent Size      Parent Free
    1015      918 rootvg                  1089536          1057792

Name                                                  File Size Optical         Access
rhcos43                                                      97 vtopt3          rw
$
$  loadopt -vtd vtopt0 -disk rhcos43
$
$ lsrep
Size(mb) Free(mb) Parent Pool         Parent Size      Parent Free
    1015      918 rootvg                  1089536          1057792

Name                                                  File Size Optical         Access
rhcos43                                                      97 vtopt0          rw
$

```

c. Boot each PowerVM LPAR from ISO and interrupt at grub. Suggested order of booting would be bootstrap, master-0, master-1, master-2, worker-*

Connect to the LPAR console (eg: via HMC) and boot the LPAR and get into the SMS menu. Once get the SMS menu follow below procedure:

```
-------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:<esc>

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Main Menu
 1.   Select Language
 2.   Setup Remote IPL (Initial Program Load)
 3.   Change SCSI Settings
 4.   Select Console
 5.   Select Boot Options


 -------------------------------------------------------------------------------
 Navigation Keys:

                                             X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:5

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Multiboot
 1.   Select Install/Boot Device
 2.   Configure Boot Device Order
 3.   Multiboot Startup <OFF>
 4.   SAN Zoning Support


 -------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:1




                              .------------------.
                              |  PLEASE WAIT.... |
                              `------------------'





 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Select Device Type
 1.   Tape
 2.   CD/DVD
 3.   Hard Drive
 4.   Network
 5.   List all Devices

 -------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:2

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Select Media Type
 1.   SCSI
 2.   SAN
 3.   SAS
 4.   SATA
 5.   USB
 6.   List All Devices

 -------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:1

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Select Media Adapter
 1.          U8247.42L.21271DA-V21-C2-T1   /vdevice/v-scsi@30000002
 2.   List all devices



 -------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:1




                              .------------------.
                              |  PLEASE WAIT.... |
                              `------------------'






check /vdevice/v-scsi@30000002/disk@8200000000000000

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Select Device
 Device  Current  Device
 Number  Position  Name
 1.        -      SCSI CD-ROM
        ( loc=U8247.42L.21271DA-V21-C2-T1-L8200000000000000 )


 -------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:1

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Select Task

SCSI CD-ROM
    ( loc=U8247.42L.21271DA-V21-C2-T1-L8200000000000000 )

 1.   Information
 2.   Normal Mode Boot
 3.   Service Mode Boot


 -------------------------------------------------------------------------------
 Navigation keys:
 M = return to Main Menu
 ESC key = return to previous screen         X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:2

 PowerPC Firmware
 Version SV810_108
 SMS 1.7 (c) Copyright IBM Corp. 2000,2008 All rights reserved.
-------------------------------------------------------------------------------
 Are you sure you want to exit System Management Services?
 1.   Yes
 2.   No


 -------------------------------------------------------------------------------
 Navigation Keys:

                                             X = eXit System Management Services
 -------------------------------------------------------------------------------
 Type menu item number and press Enter or select Navigation key:1
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
<snip>
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM                             IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM     STARTING SOFTWARE       IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM        PLEASE WAIT...       IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM                             IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
<snip>
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
-
```

Once we get the `-` after the IBM matrix , hit the `TAB` couple of times, then after some time the grub menu would be shown

Hit `e` to edit the menu


```
Elapsed time since release of system processors: 96410 mins 48 secs



      Install RHEL CoreOS


      Use the ^ and v keys to change the selection.
      Press 'e' to edit the selected item, or 'c' for a command prompt.


setparams 'Install RHEL CoreOS'

        linux /images/vmlinuz nomodeset rd.neednet=1 coreos.inst=yes
        initrd /images/initramfs.img


      Press Ctrl-x to start, Ctrl-c for a command prompt or Escape to
      discard edits and return to the menu. Pressing Tab lists
      possible completions.

```

d. Update the grub parameters with the rhos build and network details


```


setparams 'Install RHEL CoreOS'

        linux /images/vmlinuz nomodeset rd.neednet=1 coreos.inst=yes coreos.inst.install_dev=sda coreos.inst.image_url=http://<http_server_ip>/rhcos-4.3.18-ppc64le-metal.ppc64le.raw.gz coreos.inst.ignition_url=http://<http_server_ip>/<ignition_file> ip=<node_ip>::<node_gateway>:<node_netmask>:<node_fqdn>:<interface>:none nameserver=<name_server>
        initrd /images/initramfs.img



      Press Ctrl-x to start, Ctrl-c for a command prompt or Escape to
      discard edits and return to the menu. Pressing Tab lists
      possible completions.

```

`coreos.inst.ignition_url=http://<http_server_ip>/<ignition_file>  ` is the corresponding HTTP ignition file URL specific to the node. And <node_fqdn> would be <node_name><cluster_id>.<cluster_domain>. In this case would be `bootstrap.testga-187d.example.com` for bootstrap.

Press control+x to boot the LPAR 

This will take time depending on the network speed.

```
OF stdout device is: /vdevice/vty@30000000
Preparing to boot Linux version 4.18.0-147.8.1.el8_1.ppc64le (mockbuild@ppc-061.build.eng.bos.redhat.com) (gcc version 8.3.1 20190507 (Red Hat 8.3.1-4) (GCC)) #1 SMP Tue Jan 14 15:58:42 UTC 2020
Detected machine type: 0000000000000101
command line: BOOT_IMAGE=/images/vmlinuz nomodeset rd.neednet=1 coreos.inst=yes coreos.inst.
<snip>
[  OK  ] Started CoreOS Installer.
[    7.587174] coreos-installer[711]: Image size is 775676215
[    7.587692] coreos-installer[711]: tmpfs sized to 789 MB
[    7.588083] coreos-installer[711]: IGNITION_URL IS http://<HTTP_SERVER>/<ignition_file>
[    7.634617] coreos-installer[711]: Selected device is /dev/sda
[    7.635127] coreos-installer[711]: Mounting tmpfs
[    7.641624] coreos-installer[711]: Downloading install image
[    8.649566] coreos-installer[711]: 0%
[    9.659954] coreos-installer[711]: 0%
<snip>
[ 2278.774375] coreos-installer[711]: 99%
[ 2279.778696] coreos-installer[711]: Wiping /dev/sda
[ 2279.852391] coreos-installer[711]: Writing disk image
[ 2318.118866] coreos-installer[711]: Waiting for udev
[ 2318.346314] coreos-installer[711]: Embedding provided Ignition config
[ 2318.604478] coreos-installer[711]: Embedding provided networking options
[ 2318.684727] coreos-installer[711]: Not embedding additional options; none provided
[ 2318.685151] coreos-installer[711]: Not overwriting ignition platform id, no platform id provided
[ 2318.685459] coreos-installer[711]: Install complete
[  OK  ] Stopped target Remote File Systems (Pre).
<snip>
         Starting Reboot...
[  OK  ] Stopped Device-Mapper Multipath Device Controller.
[ 2324.268990] reboot: Restarting system





IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
<snip>
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM

          1 = SMS Menu                          5 = Default Boot List
          8 = Open Firmware Prompt              6 = Stored Boot List


     Memory      Keyboard     Network     Speaker
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
<snip>
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM                             IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM     STARTING SOFTWARE       IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM        PLEASE WAIT...       IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM                             IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
<snip>
IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM IBM
-
Elapsed time since release of system processors: 96465 mins 33 secs


      Red Hat Enterprise Linux CoreOS 43.81.202004201335.0 (Ootpa) (ostree:0)


      Use the ^ and v keys to change the selection.
      Press 'e' to edit the selected item, or 'c' for a command prompt.
   The selected entry will be started automatically in 0s.
OF stdout device is: /vdevice/vty@30000000
Preparing to boot Linux version 4.18.0-147.8.1.el8_1.ppc64le (mockbuild@ppc-061.build.eng.bos.redhat.com) (gcc version 8.3.1 20190507 (Red Hat 8.3.1-4) (GCC)) #1 SMP Tue Jan 14 15:58:42 UTC 2020
Detected machine type: 0000000000000101
command line: BOOT_IMAGE=(ieee1275//vdevice/vfc-client@30000003/disk@5005076802333f81\\,0000000000000000,gpt2)/ostree/
<snip>.
[  OK  ] Started Update UTMP about System Runlevel Changes.

Red Hat Enterprise Linux CoreOS 43.81.202004201335.0 (Ootpa) 4.3
SSH host key: SHA256:eLdceox2FByHp/h1cYxDjZsCh4RKZU8rV21LkoPC5w0 (ED25519)
SSH host key: SHA256:7XCSUO75luTdx41R7Gl8FHtOUcJPcMhDWFkTPYfM4gg (ECDSA)
SSH host key: SHA256:NKFd9VGHR8OdSBs7SkqJm53sH1dTkPxeJ/9GLb7kkho (RSA)
env32: <IP> fe80::f81d:72ff:fef9:6620
ocp4all5 login: core
Password:
Red Hat Enterprise Linux CoreOS 43.81.202004201335.0
  Part of OpenShift 4.3, RHCOS is a Kubernetes native operating system
  managed by the Machine Config Operator (`clusteroperator/machine-config`).

WARNING: Direct SSH access to machines is not recommended; instead,
make configuration changes via `machineconfig` objects:
  https://docs.openshift.com/container-platform/4.3/architecture/architecture-rhcos.html

---
[core@ocp4all5 ~]$
[core@ocp4all5 ~]$
[core@ocp4all5 ~]$ ifconfig
env32: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet <IP>  netmask 255.255.240.0  broadcast <BROADCAST>
        inet6 fe80::f81d:72ff:fef9:6620  prefixlen 64  scopeid 0x20<link>
        ether fa:1d:72:f9:66:20  txqueuelen 1000  (Ethernet)
        RX packets 7207  bytes 478919 (467.6 KiB)
        RX errors 0  dropped 2  overruns 0  frame 0
        TX packets 47  bytes 3820 (3.7 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        device interrupt 32

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 24  bytes 2208 (2.1 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 24  bytes 2208 (2.1 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

[core@ocp4all5 ~]$
```


**4. Initiate the bootstrap process**

Run 
`openshift-install --dir=<installation_directory> wait-for bootstrap-complete  --log-level=info`

**5. Install and setup OC client**

This can be done on any host you prefer to use for interacting with the cluster. In this document `oc` is setting up the bastion host itself

a. Download `https://mirror.openshift.com/pub/openshift-v4/ppc64le/clients/ocp/candidate-4.3/openshift-client-linux-4.3.18.tar.gz` and extract and make the oc binary available in PATH.

b. Create /root/.kubeconfig file
   The file is present in the OpenShift installer’s auth directory.

**6. Approve all pending CSR requests from the bootstrap MCO and the worker nodes**

Run `oc get csr -ojson | jq -r '.items[] | select(.status == {} ) | .metadata.name' | xargs oc adm certificate approve`

**7. Wait for all cluster operators to come online**
Run  `oc get co`

The authentication, ingress and monitoring co's will take some time to be Available. Review for any pending CSR’s in the queue and approve them again. Wait for some more time for the pending co's to come online.

**8.  Patch the image config registry**

The image-registry is not always available immediately after the OCPinstaller

Run below

```
while [ $(oc get configs.imageregistry.operator.openshift.io/cluster | wc -l) == 0 ]; do sleep 30; done
oc patch configs.imageregistry.operator.openshift.io cluster --type merge --patch '{"spec":{"storage":{"emptyDir":{}}, "managementState": "Managed"}}'
```
**9.  Complete the installation**

Once all the cluster Operators are AVAILABLE, run

`openshift-install --dir=<installation_directory> wait-for install-complete`

```
INFO Waiting up to 30m0s for the cluster to initialize...
```
**10. Validating the cluster**

a. oc get pods --all-namespaces
b. oc get nodes
c. oc get co
d. Launch the UI and ensure it is accessible.

