# **Table of Contents**

- [Introduction](#introduction)
- [Pre-requisites](#pre-requisites)
- [Image and LPAR requirements](#image-and-lpar-requirements)
- [OCP Install](#ocp-install)


# Introduction
This repo contains Terraform templates to help deployment of OpenShift Container Platform (OCP) 4.x on PowerVM LPARs.
This assumes PowerVC is used as the IaaS layer for managing PowerVM LPARs.

If you are using standalone PowerVM please take a look at the [ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) to setup helper node (bastion) for OCP deployment.

This project also leverages the same ansible playbook internally for OCP deployment.

Run this code from either Mac or Linux (Intel) system.

:heavy_exclamation_mark: *This automation is intended for test/development purposes only and there is no formal support. For issues please open a GitHub issue*

# Pre-requisites

You need to identify a remote client machine for running the automation. This could be your laptop or a VM. Install the below required packages on the client machine.

- **Git**: Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions
on installing the latest Git.
- **Terraform**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. You'll need to use version `0.12.20` or later. For validating the version run `terraform version` command after install.


# Image and LPAR requirements

You'll need to create RedHat CoreOS (RHCOS) and RHEL 8.0 (or later) image in PowerVC. For RHCOS image creation, follow the steps mentioned
[here](./docs/coreos-image-creation.md).
Following are the recommended LPAR configs for OpenShift nodes
- Bootstrap, Master - 2 vCPUs, 16GB RAM, 120 GB Disk.

  PowerVM LPARs by default uses SMT=8. So with 2vCPUs, the number of logical CPUs as seen by the Operating System will be **16** (`2 vCPUs x 8 SMT`)

   **_This config is suitable for majority of the scenarios_**
- Worker - 2 vCPUs, 16GB RAM, 120 GB Disk

   **_Increase worker vCPUs, RAM and Disk based on application requirements_**


# OCP Install

Follow these [quickstart](docs/quickstart.md) steps to kickstart OCP installation on PowerVM
