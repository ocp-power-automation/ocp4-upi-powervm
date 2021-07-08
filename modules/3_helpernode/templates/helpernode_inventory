[vmhost]
%{ for ip in bastion_ip ~}
${ip} ansible_connection=ssh ansible_user=${rhel_username}
%{ endfor ~}
