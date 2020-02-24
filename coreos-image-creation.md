
1. Download and extract the CoreOS image with suffix *-openstack.ppc64le.qcow2.gz*.
   For example download the current one from the following location and extract it.

2. Convert the CoreOS qcow2 image to raw image
   ```
   qemu-img convert -f qcow2 -O raw <image>.qcow2 <image>.raw
   ```

3. Attach a new volume with required size ( eg 20G)to an existing PowerVC VM and restart it. Please take a note of the new volume.

4. Once the VM is up, get the CoreOS raw image to this VM and dump the raw image to the newly added disk
   ```
   dd if=<image>.raw of=/dev/<device> bs=4M
   ```
   where `<device>` is the newly added device

5. Detach the newly added Volume, from the VM

6. Go to PowerVC UI ->images and select create for creating a new image

7. Specify `image name` and choose `PowerVM` for Hypervisor type, `RHEL` for Operating system and `littleEndian` for Endianness

8. Select Add Volume and search for the specific volume name (where you dd-ed the CoreOS image ) and set Boot set to yes.

9. Create the image by clicking on create
