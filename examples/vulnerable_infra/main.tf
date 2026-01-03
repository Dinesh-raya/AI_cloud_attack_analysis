# VULNERABLE TERRAFORM INFRASTRUCTURE
# Demonstrates: Internet -> EC2 -> Role -> Bedrock -> S3

provider "aws" {
  region = "us-east-1"
}

# 1. Public EC2 Instance
resource "aws_instance" "app_server" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.allow_all.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  
  tags = {
    Name = "Public-AI-FrontEnd"
  }
}

# 2. Over-permissive Security Group (0.0.0.0/0)
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. IAM Role for EC2
resource "aws_iam_role" "ec2_ai_role" {
  name = "ec2_ai_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_ai_role.name
}

# 4. Dangerous Policy (Admin Access / Broad S3+Bedrock)
resource "aws_iam_policy" "ai_admin_policy" {
  name        = "ai_admin_policy"
  description = "Too permissive"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*"
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_admin" {
  role       = aws_iam_role.ec2_ai_role.name
  policy_arn = aws_iam_policy.ai_admin_policy.arn
}

# 5. AI Service (Bedrock Logging)
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    embedding_data_delivery_enabled = true
    image_data_delivery_enabled     = true
    text_data_delivery_enabled      = true
    
    s3_config {
      bucket_name = aws_s3_bucket.ai_logs.bucket
    }
  }
}

# 6. Public S3 Bucket (The Target)
resource "aws_s3_bucket" "ai_logs" {
  bucket = "company-ai-prompt-logs-sensitive"
  acl    = "public-read" # VULNERABILITY
}
