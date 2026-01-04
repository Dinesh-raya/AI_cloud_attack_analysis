# Demo Scenario: Over-privileged IAM Configuration
# Risk: Wildcard permissions enabling lateral movement

resource "aws_iam_role" "lambda_processor" {
  name = "LLMDataProcessorRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# VULNERABILITY: Wildcard permissions on all resources
resource "aws_iam_role_policy" "lambda_full_access" {
  name = "FullAccessPolicy"
  role = aws_iam_role.lambda_processor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "data_processor" {
  filename      = "processor.zip"
  function_name = "llm-data-processor"
  role          = aws_iam_role.lambda_processor.arn
  handler       = "index.handler"
  runtime       = "python3.10"

  environment {
    variables = {
      TRAINING_BUCKET = "company-llm-training-data"
    }
  }
}

# VULNERABILITY: Public security group for debugging left in production
resource "aws_security_group" "debug_sg" {
  name        = "debug-access"
  description = "Temporary debug access - REMOVE BEFORE PROD"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
