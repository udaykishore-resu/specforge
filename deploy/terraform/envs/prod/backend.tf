# Remote state, configured per account.
#
# No bucket name is committed: hard-coding one ties this repository to a single
# AWS account, and the first thing anyone forking it would have to do is edit a
# file that is not theirs to edit.
#
#   terraform init -backend-config=backend.hcl
#
# backend.hcl (not committed):
#   bucket         = "acme-terraform-state"
#   key            = "specforge/prod/terraform.tfstate"
#   region         = "eu-west-1"
#   dynamodb_table = "terraform-locks"
#   encrypt        = true

terraform {
  backend "s3" {}
}
