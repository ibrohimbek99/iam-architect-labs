# Plan-only by default (docs/adr/0003). These flags let `terraform plan` run with
# no AWS credentials at all, so nothing can be created in a real account by
# accident. Remove them only for an approved, budgeted apply in a personal account.
provider "aws" {
  region                      = var.region
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true

  default_tags {
    tags = {
      project     = "iam-architect-labs"
      environment = var.environment
      managed_by  = "terraform"
    }
  }
}
