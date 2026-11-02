# re-install within 7 days of --destroy: new log bucket id
log_bucket_id = "agy-example-s2"
consumer_tier_hosts = ["consumer-ai.example.com"]
seat_user_groups = { "dev1@example.com" = "agy-dev" }
evidence_name_suffix = "s2"
cas_template_suffix = "s2"
seat_contain_exempt = ["admin@example.com"]
enable_windows_image_pipeline = true
deploy_windows_workstation = true
windows_image              = "projects/example-agy-project/global/images/family/agy-win2025-dev"
windows_workstation_client_mode = "gateway"
