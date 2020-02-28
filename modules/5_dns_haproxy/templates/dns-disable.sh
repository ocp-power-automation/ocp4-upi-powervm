etc_named_conf=/etc/named.conf
etc_named_zones_dir=/etc/named/zones
etc_resolv_conf=/etc/resolv.conf


echo "Disabling DNS Server..."

sudo systemctl disable --now named
# Not uninstalling bind-chroot as it may be in use.

if [[ -f $etc_named_conf.orig ]]; then
    sudo mv $etc_named_conf.orig $etc_named_conf
else
    sudo rm -f $etc_named_conf
fi
if [[ -f $etc_resolv_conf.orig ]]; then
    sudo mv $etc_resolv_conf.orig $etc_resolv_conf
else
    sudo rm -f $etc_resolv_conf
fi
sudo rm -rf $etc_named_zones_dir

sudo firewall-cmd --remove-service=dns --permanent
sudo firewall-cmd --reload

echo "Disabled DNS Server."
