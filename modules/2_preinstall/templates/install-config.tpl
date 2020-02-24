apiVersion: v1
baseDomain: ${cluster_domain}
compute:
- hyperthreading: Enabled
  name: worker
  platform: {}
  replicas: 0
controlPlane:
  hyperthreading: Enabled
  name: master
  platform: {}
  replicas: ${master_count}
metadata:
  creationTimestamp: null
  name: ${cluster_id}
networking:
  clusterNetwork:
  - cidr: 10.128.0.0/14
    hostPrefix: 23
  networkType: OpenShiftSDN
  serviceNetwork:
  - 172.30.0.0/16
platform:
  none: {}
pullSecret: '${pull_secret}'
sshKey: |
  ${public_ssh_key}
