################################################################
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Licensed Materials - Property of IBM
#
# ©Copyright IBM Corp. 2020
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

locals {
  # -- Used for rendering BIND config files ---

  # Terraform doesn't have a "cidrreversezone" function that computes the prefix of a
  # DNS reverse zone given a CIDR block, so the following is a quick and dirty partial
  # implemention of such computation.  It works only for IPV4, and moreover only when the
  # subnet prefix ends on an octet boundary (/8, /16, /24).
#  int_sn_pfx_octet_ct   = "${tonumber(split("/", ${var.cidr_block})[1]) / 8 }
#  int_net_cidr_octets   = "${split(".", cidrhost(${var.cidr_block}, 0))}
#  rev_indexes           = [for ix in range(local.int_sn_pfx_octet_ct): local.int_sn_pfx_octet_ct - ix -1]
#  int_sn_pfx_rev_octets = [for ix in local.rev_indexes: local.int_net_cidr_octets[ix]]
#  reverse_zone = join(".", local.int_sn_pfx_rev_octets)
    
    
    master_info = [for ix in range(length(var.master_ips)): {index = ix, ip = var.master_ips[ix]}]
    worker_info = [for ix in range(length(var.worker_ips)): {index = ix, ip = var.worker_ips[ix]}]
    named_cfg = {
        cluster_zone        = "${var.cluster_id}.${var.cluster_domain}"
        cluster_id          = var.cluster_id
        cluster_domain      = var.cluster_domain
        #skip for now
        #reverse_zone_pfx   = "${local.reverse_zone}"

        zone_serial_number = formatdate("YYMMDDhhmm", timestamp())

        forward_to_dns_ip    = "8.8.8.8"
        external_zone_dns_ip = var.bastion_ip
#        internal_zone_dns_ip = var.bastion_ip

        load_balancer_external_ip = var.bastion_ip
        load_balancer_internal_ip = var.bastion_ip
        ingress_external_ip = var.bastion_ip

        masters = local.master_info
        workers = local.worker_info

        bootstrap_ip    = var.bootstrap_ip
    }
}

