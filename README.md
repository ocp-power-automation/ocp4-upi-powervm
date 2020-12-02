# **Table of Contents**

- [**Table of Contents**](#table-of-contents)
- [Introduction](#introduction)
  - [Automation Host Prerequisites](#automation-host-prerequisites)
  - [PowerVC Prerequisites](#powervc-prerequisites)
  - [OCP Install](#ocp-install)
  - [Contributing](#contributing)


# Introduction
The `ocp4-upi-powervm` [project](https://github.com/ocp-power-automation/ocp4-upi-powervm) provides Terraform based automation code to help the deployment of OpenShift Container Platform (OCP) 4.x on PowerVM systems managed by PowerVC.

If you are using standalone PowerVM please take a look at the [following quickstart guide](https://github.com/RedHatOfficial/ocp4-helpernode/blob/devel/docs/quickstart-powervm.md)
which uses the [ansible playbook](https://github.com/RedHatOfficial/ocp4-helpernode) to setup a helper node (bastion) for OCP deployment.

This project also leverages the same ansible playbook internally for OCP deployment on PowerVM LPARs managed via PowerVC.

!!! Note
        For bugs/enhancement requests etc. please open a GitHub [issue](https://github.com/ocp-power-automation/ocp4-upi-powervm/issues)

!!! Warning
          **The [main](https://github.com/ocp-power-automation/ocp4-upi-powervm/tree/master) branch must be used with latest OCP pre-release versions only. For stable releases please checkout specific release branches -{[release-4.5](https://github.com/ocp-power-automation/ocp4-upi-powervm/tree/release-4.5), [release-4.6](https://github.com/ocp-power-automation/ocp4-upi-powervm/tree/release-4.6) ...} and follow the docs in the specific release branches.**

## Automation Host Prerequisites

The automation needs to run from a system with internet access. This could be your laptop or a VM with public internet connectivity. This automation code has been tested on the following 64-bit Operating Systems:
- Mac OSX (Darwin)
- Linux (x86_64)

Follow the [guide](docs/automation_host_prereqs.md) to complete the prerequisites.


## PowerVC Prerequisites

Follow the [guide](docs/ocp_prereqs_powervc.md) to complete the PowerVC prerequisites.

## OCP Install

Follow the [quickstart](docs/quickstart.md) guide for OCP installation on PowerVM LPARs managed via PowerVC

## Contributing
Please see the [contributing doc](CONTRIBUTING.md) for more details.
PRs are most welcome !!
