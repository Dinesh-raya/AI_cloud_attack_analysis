resource "aws_sagemaker_notebook_instance" "researcher_notebook" {
  name          = "ai-research-notebook"
  role_arn      = aws_iam_role.notebook_role.arn
  instance_type = "ml.t3.medium"
  
  # Potential exposure via presigned URL leak or misconfigured network
  direct_internet_access = "Enabled"
}

resource "aws_iam_role" "notebook_role" {
  name = "SageMakerExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.notebook_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
