#!/bin/bash

#Scan devices
sudo rescan-scsi-bus.sh -a -m -r

storage_device=""
storage_disk_name=${disk_name}

if [[ -z $(ls -l /dev/mapper/mpath*) ]];then
    disk_path=/dev/sd*
    echo "Disk path is /dev/sd*"
else
    disk_path=/dev/mapper/mpath*
    echo "Disk path is /dev/mapper/mpath*"
fi

for device in $(ls -1 $disk_path|egrep -v "[0-9]$"); do
    if [[ ! -b $device"1" ]]; then
        # Convert disk size to GB
        device_size=$(lsblk -b -dn -o SIZE $device | awk '{print $1/1073741824}')
        if [[ -z $storage_device && $device_size == ${volume_size} ]]; then
            storage_device=$device
            echo "Storage disk is $device"
            # This symbolic link is used in openshift config
            echo "ENV{DEVTYPE}==\"disk\", ENV{SUBSYSTEM}==\"block\", ENV{DEVPATH}==\"$(sudo udevadm info --root --name="$storage_device" | sudo grep DEVPATH | sudo cut -f2 -d'=')\" SYMLINK+=\"$storage_disk_name\"" | sudo tee /lib/udev/rules.d/10-custom-ocp.rules;
            sudo udevadm control --reload-rules;
            sudo udevadm trigger --type=devices --action=change
            break
        fi
    fi
done

# Verify the disk link exist
timeout 10 bash -c -- "
while [ ! -L /dev/$storage_disk_name ]; do
    echo 'Disk not ready, sleeping for 2s..';
    sleep 2;
done
"
