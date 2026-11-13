---
name: terraform-iac
description: Terraform HCL patterns, state management, modules, AWS/GCP resource provisioning
metadata:
  type: skill
  triggers: ["terraform", "iac", "infrastructure as code", "tf", "hcl", "aws infra"]
---

# Terraform Patterns

## Module structure
```
infra/
  main.tf           variables.tf  outputs.tf
  terraform.tfvars  # gitignore if secrets
  modules/
    vpc/  database/  compute/
```

## Remote state
```hcl
terraform {
  backend "s3" {
    bucket         = "my-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "tf-lock"
  }
}
```

## Resource example (AWS RDS)
```hcl
resource "aws_db_instance" "main" {
  identifier        = "myapp-${var.env}"
  engine            = "postgres"
  engine_version    = "16"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  password          = random_password.db.result
  backup_retention_period = 7
  deletion_protection     = true
}
```

## Workflow
```bash
terraform init
terraform plan    # preview
terraform apply   # requires approval
terraform destroy
```

## Rules
- Remote state + DynamoDB locking always
- `terraform fmt` before commit
- Never store secrets in .tfvars — use env vars or secrets manager
- Modules for anything used > once
