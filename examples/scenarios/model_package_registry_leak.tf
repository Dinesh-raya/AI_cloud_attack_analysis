resource "aws_sagemaker_model_package_group" "secret_models" {
  model_package_group_name = "proprietary-llm-models"
  model_package_group_description = "Our core business logic models"
}

# Vulnerability: Resource policy allows external or anonymous access
resource "aws_sagemaker_model_package_group_policy" "leak" {
  model_package_group_name = aws_sagemaker_model_package_group.secret_models.model_package_group_name
  resource_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicModelAccess"
      Effect    = "Allow"
      Principal = "*"
      Action    = "sagemaker:DescribeModelPackage"
      Resource  = aws_sagemaker_model_package_group.secret_models.arn
    }]
  })
}
