variable "region" {
  description = "Region for Roles Anywhere and both buckets. All three accounts use this region."
  type        = string
  default     = "ap-southeast-1"
}

variable "name_prefix" {
  description = "Optional prefix if PaymentReconcilerRole already exists in the identity account."
  type        = string
  default     = ""
}

variable "issuing_ca_pem_path" {
  description = "PEM of the issuing CA only. Do not include the root."
  type        = string
}

variable "session_duration_seconds" {
  description = "Profile duration. API default is 3600. Maximum is 43200 (12 hours)."
  type        = number
  default     = 3600

  validation {
    condition     = var.session_duration_seconds >= 900 && var.session_duration_seconds <= 43200
    error_message = "durationSeconds must be between 900 and 43200."
  }
}

variable "identity_access_key" {
  description = "Admin access key for the identity account. Not written into the repo."
  type        = string
  sensitive   = true
}

variable "identity_secret_key" {
  description = "Admin secret key for the identity account."
  type        = string
  sensitive   = true
}

variable "identity_session_token" {
  description = "Session token for the identity account. Empty for long-term keys."
  type        = string
  sensitive   = true
  default     = ""
}

variable "payment_access_key" {
  description = "Admin access key for the payment account."
  type        = string
  sensitive   = true
}

variable "payment_secret_key" {
  description = "Admin secret key for the payment account."
  type        = string
  sensitive   = true
}

variable "payment_session_token" {
  description = "Session token for the payment account. Empty for long-term keys."
  type        = string
  sensitive   = true
  default     = ""
}

variable "inventory_access_key" {
  description = "Admin access key for the inventory account."
  type        = string
  sensitive   = true
}

variable "inventory_secret_key" {
  description = "Admin secret key for the inventory account."
  type        = string
  sensitive   = true
}

variable "inventory_session_token" {
  description = "Session token for the inventory account. Empty for long-term keys."
  type        = string
  sensitive   = true
  default     = ""
}
