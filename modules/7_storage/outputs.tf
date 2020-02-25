output "storageclass_name" {
    depends_on = [null_resource.configure_nfs_storage]
    value = var.storage_type == "nfs" ? local.nfs_storageclass_config.storageclass_name : "N/A" #Add other storageclass names here
}

