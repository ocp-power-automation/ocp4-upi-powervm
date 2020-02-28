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

if [[ -f $etc_resolv_conf ]]; then
    sudo cp $etc_resolv_conf $etc_resolv_conf.orig
fi

sudo sed -i '/search /a nameserver ${bastion_ip}' $etc_resolv_conf
sudo chcon -R -t named_conf_t $etc_resolv_conf

#systemd config to restart DNS
named_systemd_dir=/usr/lib/systemd/system/named.service.d
sudo mkdir -p $named_systemd_dir
sudo chmod 755 $named_systemd_dir
echo "[Service]" | sudo tee $named_systemd_dir/restart.conf
echo "Restart=always" | sudo tee -a $named_systemd_dir/restart.conf
echo "RestartSec=3" | sudo tee -a $named_systemd_dir/restart.conf

echo "Enabled DNS Server."
