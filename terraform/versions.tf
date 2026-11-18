terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.70.0"
    }
  }
}

provider "aws" {
  region     = var.region
  access_key = var.identity_access_key
  secret_key = var.identity_secret_key
  token      = var.identity_session_token != "" ? var.identity_session_token : null
}

provider "aws" {
  alias      = "payment"
  region     = var.region
  access_key = var.payment_access_key
  secret_key = var.payment_secret_key
  token      = var.payment_session_token != "" ? var.payment_session_token : null
}

provider "aws" {
  alias      = "inventory"
  region     = var.region
  access_key = var.inventory_access_key
  secret_key = var.inventory_secret_key
  token      = var.inventory_session_token != "" ? var.inventory_session_token : null
}
