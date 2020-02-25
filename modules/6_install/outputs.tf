output "install_status" {
    depends_on = [null_resource.wait_install]
    value = "COMPLETED"
}

