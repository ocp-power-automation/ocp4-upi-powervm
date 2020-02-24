cd ~/openstack-upi

for index in $(seq 0 ${master_count}); do
sudo cp master.ign /var/www/html/master-$index.json
sudo chmod 755 /var/www/html/master-$index.json
done

# TODO: CONFIGURE FOR WORKERS
for index in $(seq 0 ${master_count}); do
sudo cp worker.ign /var/www/html/worker-$index.json
sudo chmod 755 /var/www/html/worker-$index.json
done

