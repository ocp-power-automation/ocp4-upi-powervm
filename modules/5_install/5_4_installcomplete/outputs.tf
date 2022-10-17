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
# ©Copyright IBM Corp. 2022
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################

output "install_status" {
  depends_on = [null_resource.install]
  value      = "COMPLETED"
}

output "oc_server_url" {
  depends_on = [null_resource.install]
  value      = "https://api.${var.cluster_id}.${local.cluster_domain}:6443"
}

output "web_console_url" {
  depends_on = [null_resource.install]
  value      = "https://console-openshift-console.apps.${var.cluster_id}.${local.cluster_domain}"
}
