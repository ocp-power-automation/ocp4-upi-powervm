output "storageclass_name" {
    depends_on = [null_resource.configure_nfs_storage]
    value = local.storageclass_config.storageclass_name
}
