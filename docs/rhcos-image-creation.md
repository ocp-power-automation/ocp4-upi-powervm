- [Introduction](#introduction)
  - [Option-1](#option-1)
  - [Option-2](#option-2)

# Introduction
Depending on your environment you can follow one of the options to create RHCOS (CoreOS) image in PowerVC

## Option-1

1. Download the RHCOS image from the following [link](https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.6/latest/rhcos-openstack.ppc64le.qcow2.gz) on a system with public internet access.
You'll need a way to transfer this image to a RHEL VM that you'll create in the next step.
2. Login to PowerVC and create a RHEL 8.x VM having an additional empty volume with minimum size of 120G. **Please make a note of the new volume name**.
3. Login to the VM and execute the following steps
   1. Install `wget`, `qemu-img`, `parted` and `gzip` packages
   2. Transfer the downloaded RHCOS image to this VM
   3. Extract the image
      ```
      $ gunzip rhcos-openstack.ppc64le.qcow2.gz
      ```
   4. Convert the CoreOS qcow2 image to raw image
      ```
      $ qemu-img convert -f qcow2 -O raw rhcos-openstack.ppc64le.qcow2 rhcos-latest.raw
      ```
   5. Identify the disk device representing the additional empty volume attached to the VM
      ```
      $ disk_device_list=$(sudo parted -l 2>&1 | grep -E -v "$readonly" | grep -E -i "ERROR:" |cut -f2 -d: | grep -v "Can't" | xargs -i echo "Disk.{}:|" | xargs echo | tr -d ' ' | rev | cut -c2- | rev)
      $ empty_disk_device=$(sudo fdisk -l | grep -E "$disk_list" | sort -k5nr | head -n 1 | tail -n1 | cut -f1 -d: | cut -f2 -d' ')
      $ echo "$empty_disk_device"'
      ```
   6. Dump the raw image to the newly added disk
      ```
      $ dd if=rhcos-latest.raw of=${empty_disk_device} bs=4M
      ```
      where `${empty_disk_device}` is the device representing the attached volume

4. Detach the volume, from the VM

5. Go to PowerVC UI->images and select **create** for creating a new image

6. Specify `image name` and choose `PowerVM` for Hypervisor type, `RHEL` for Operating system and `littleEndian` for Endianness

7.  Select **Add Volume** and search for the specific volume name (where you dd-ed the RHCOS image ) and set **Boot set** to yes.

8.  Create the image by clicking on **create**

## Option-2

Creating and importing RHCOS OVA image

1. Download the RHCOS image from the following [link](https://mirror.openshift.com/pub/openshift-v4/ppc64le/dependencies/rhcos/4.6/latest/rhcos-openstack.ppc64le.qcow2.gz) on a system with public internet access.
You'll need a way to transfer this image to a RHEL VM that you'll create in the next step.
2. Login to PowerVC and create a RHEL 8.x VM
3. Use the script https://github.com/ocp-power-automation/infra/blob/master/scripts/images/convert_qcow2_ova.py and
   convert the RHCOS qcow2 image to an OVA formatted image.
4. Follow the steps mentioned in [PowerVC docs](https://www.ibm.com/support/knowledgecenter/SSVSPA_1.4.4/com.ibm.powervc.cloud.help.doc/powervc_import_image_cloud.html) to
   import the OVA image.
