# Demo Scenario: Insecure SageMaker Notebook
# Risk: Direct internet access + over-permissive IAM role

resource "aws_sagemaker_notebook_instance" "training_notebook" {
  name          = "ml-training-notebook"
  role_arn      = aws_iam_role.sagemaker_role.arn
  instance_type = "ml.t3.xlarge"

  # VULNERABILITY: Direct internet access enabled
  direct_internet_access = "Enabled"

  tags = {
    Environment = "production"
    Team        = "ml-research"
  }
}

resource "aws_iam_role" "sagemaker_role" {
  name = "SageMakerExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "sagemaker.amazonaws.com"
      }
    }]
  })
}

# VULNERABILITY: Overly permissive policy attachment
resource "aws_iam_role_policy_attachment" "sagemaker_admin" {
  role       = aws_iam_role.sagemaker_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
