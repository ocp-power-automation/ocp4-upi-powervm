#Scan devices
sudo rescan-scsi-bus.sh -a -m

storage_device=""
for device in $(ls -1 /dev/mapper/mpath*|egrep -v "[0-9]$"); do
    if [[ ! -b $device"1" ]]; then
        # Convert disk size to GB
        device_size=$(lsblk -b -dn -o SIZE $device | awk '{print $1/1073741824}')
        if [[ -z $storage_device && $device_size == ${nfs_volume_size} ]]; then
            storage_device=$device
            # This symbolic link is used in openshift config
            storage_disk_name=${disk_name}
            echo "ENV{DEVTYPE}==\"disk\", ENV{SUBSYSTEM}==\"block\", ENV{DEVPATH}==\"$(sudo udevadm info --root --name="$storage_device" | sudo grep DEVPATH | sudo cut -f2 -d'=')\" SYMLINK+=\"$storage_disk_name\"" | sudo tee -a /lib/udev/rules.d/10-custom-ocp.rules;
            sudo udevadm control --reload-rules;
            sudo udevadm trigger --type=devices --action=change
        fi
    fi
done

