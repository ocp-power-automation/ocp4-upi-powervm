output "init_status" {
    depends_on = [null_resource.ocp_init]
    value = "COMPLETED"
}
