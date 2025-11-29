# **PowerVC Prerequisites**

## RHCOS and RHEL Images for OpenShift
You'll need to create Red Hat CoreOS (RHCOS) and RHEL 9.2 (or later) images in PowerVC. RHEL 9.x or 10.x image is used by bastion node, and RHCOS image is used for boostrap, master and worker nodes.


For RHCOS image creation, follow the steps mentioned
in the following [doc](./rhcos-image-creation.md).

For RHEL image creation follow the steps mentioned in the following [doc](https://www.ibm.com/docs/en/powervc/2.0.3?topic=working-images
) , you may either create a new image from ISO, or use a similar method like CoreOS with a qcow2 image.


## Compute Templates

You'll need to create [compute templates](https://www.ibm.com/support/knowledgecenter/en/SSXK2N_1.4.4/com.ibm.powervc.standard.help.doc/powervc_compute_template_hmc.html
) for bastion, bootstrap, master and worker nodes.

Following are the recommended LPAR configs that you can use when creating the compute templates for different type of nodes

- Bootstrap - 2 vCPUs, 16GB RAM, 120 GB Disk.

- Master - 2 vCPUs, 32GB RAM, 120 GB Disk.

  PowerVM LPARs by default uses SMT=8. So with 2vCPUs, the number of logical CPUs as seen by the Operating System will be **16** (`2 vCPUs x 8 SMT`)

   **_This config is suitable for majority of the scenarios_**

- Worker - 2 vCPUs, 32GB RAM, 120 GB Disk

   **_Increase worker vCPUs, RAM and Disk based on application requirements_**

- Bastion - 2vCPUs, 16GB RAM, 200 GB Disk

   **_Increase bastion vCPUs, RAM and Disk based on application requirements_**
