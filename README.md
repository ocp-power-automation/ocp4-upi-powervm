# **Table of Contents**

- [**Table of Contents**](#table-of-contents)
- [Introduction](#introduction)
  - [Automation Host Prerequisites](#automation-host-prerequisites)
  - [PowerVC Prerequisites](#powervc-prerequisites)
  - [OCP Install](#ocp-install)
  - [Contributing](#contributing)


# Introduction
This repo contains Terraform templates to help deployment of OpenShift Container Platform (OCP) 4.6.x on PowerVM LPARs.
This assumes PowerVC is used as the IaaS layer for managing the PowerVM LPARs.

If you are using standalone PowerVM please take a look at the [following quickstart guide](https://github.com/RedHatOfficial/ocp4-helpernode/blob/devel/docs/quickstart-powervm.md)
which uses the [ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) to setup helper node (bastion) for OCP deployment.

This project also leverages the same ansible playbook internally for OCP deployment on PowerVM LPARs managed via PowerVC.


:heavy_exclamation_mark: *For bugs/enhancement requests etc. please open a GitHub issue*

:information_source: **This (release-4.6) branch must be used with OCP 4.6.x versions only.**

## Automation Host Prerequisites

The automation needs to run from a system with internet access. This could be your laptop or a VM with public internet connectivity. This automation code have been tested on the following 64-bit Operating Systems:
- Mac OSX (Darwin)
- Linux (x86_64)

Follow the [guide](docs/automation_host_prereqs.md) to complete the prerequisites.


## PowerVC Prerequisites

Follow the [guide](docs/ocp_prereqs_powervc.md) to complete the PowerVC prerequisites.

## OCP Install

Follow the [quickstart](docs/quickstart.md) guide for OCP installation on PowerVM LPARs managed via PowerVC

## Contributing
Please see the [contributing doc](https://github.com/ocp-power-automation/ocp4-upi-powervm/blob/master/CONTRIBUTING.md) for more details.
PRs are most welcome !!
