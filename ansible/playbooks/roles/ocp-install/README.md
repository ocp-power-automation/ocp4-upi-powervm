ocp-install: OCP Configuration
=========

This module will:

 1. Approve pending worker CSRs.
 1. Setup kubeconfig at `~/.kube/config`.
 1. Wait till cluster install is completed.
 1. Patch image registry to EmptyDir if storage_type is not 'nfs'.

Requirements
------------

 - The wait-for bootstrap-complete command should succeed before running this role.
 - The no of worker nodes already created.
 - Worker count can be extracted from host group 'workers'.

Role Variables
--------------

| Variable                | Required | Default        | Comments                                    |
|-------------------------|----------|----------------|---------------------------------------------|
| workdir                 | no       | ~/ocp4-workdir | Place for config generation and auth files  |
| log_level               | no       | info           | Option --log-level in openshift-install cmd |
| release_image_override  | no       | ""             | OCP image overide variable                  |
| storage_type            | no       | none           | Storage type set for the cluster: Eg: nfs   |
| worker_count            | yes      |                | Number of worker nodes                      |

Dependencies
------------

 - ocp-config
 - nodes-config

Example Playbook
----------------

    - name: Install OCP
      hosts: bastion
      roles:
      - ocp-install
      vars:
        worker_count: "{{ groups['workers'] | length }}"

License
-------

See LICENCE.txt

Author Information
------------------

Yussuf Shaikh (yussuf@us.ibm.com)
