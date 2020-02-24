etc_named_conf=/etc/named.conf
etc_named_zones_dir=/etc/named/zones
etc_resolv_conf=/etc/resolv.conf

sudo yum install bind-chroot -y
sudo firewall-cmd --add-service=dns --permanent
sudo firewall-cmd --reload

echo "Enabling DNS Server..."
if [[ -f $etc_named_conf ]]; then
   sudo mv $etc_named_conf $etc_named_conf.orig
fi
sudo cp ${sourcedir}/named.conf $etc_named_conf
sudo chcon -t named_conf_t $etc_named_conf

sudo mkdir -p $etc_named_zones_dir
sudo cp -p ${sourcedir}/*.db $etc_named_zones_dir
sudo chcon -R -t named_conf_t $etc_named_zones_dir

sudo systemctl enable --now named

#if [[ -f $etc_resolv_conf ]]; then
#   sudo mv $etc_resolv_conf $etc_resolv_conf.orig
#fi
#sudo cp ${sourcedir}/resolv.conf $etc_resolv_conf
#sudo chcon -R -t net_conf_t $etc_resolv_conf

sudo sed -i '/search /a nameserver ${bastion_ip}' $etc_resolv_conf

echo "Enabled DNS Server."

