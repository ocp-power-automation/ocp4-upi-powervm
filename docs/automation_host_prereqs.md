# Automation Host Prerequisites
- [Automation Host Prerequisites](#automation-host-prerequisites)
  - [Automation Host Setup](#automation-host-setup)
    - [Configure Your Firewall](#configure-your-firewall)
    - [Terraform](#terraform)
    - [Git](#git)

## Automation Host Setup

Install the following packages on the automation host. Select the appropriate install binaries based on your automation host platform - Mac/Linux.

### Configure Your Firewall
If your system is behind a firewall, you will need to ensure the following ports are open in order to use ssh, http, and https:
- 22, 443, 80

These additional ports are required for the ocp cli (`oc`) post-install:
- 6443

### Terraform

**Terraform >= 0.13.0**: Please refer to the [link](https://learn.hashicorp.com/terraform/getting-started/install.html) for instructions on installing Terraform. For validating the version run `terraform version` command after install.

### Git

**Git**:  Please refer to the [link](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for instructions on installing Git.
