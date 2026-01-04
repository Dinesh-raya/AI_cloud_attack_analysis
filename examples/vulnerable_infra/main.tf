# VULNERABLE TERRAFORM INFRASTRUCTURE
# Demonstrates: Internet -> EC2 -> Role -> Bedrock Agent -> Agent Role -> S3 (Prompt Injection Path)

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
    Statement = [{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_ai_role.name
}

# 3b. Policy for EC2 to Invoke Agent
resource "aws_iam_policy" "invoke_agent_policy" {
  name = "invoke_agent_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
        Action = "bedrock:InvokeAgent"
        Effect = "Allow"
        Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_invoke" {
  role       = aws_iam_role.ec2_ai_role.name
  policy_arn = aws_iam_policy.invoke_agent_policy.arn
}


# 4. Bedrock Agent (The new Attack Surface)
resource "aws_bedrock_agent" "financial_agent" {
  agent_name = "financial-agent"
  agent_resource_role_arn = aws_iam_role.agent_role.arn
  foundation_model = "anthropic.claude-v2"
}

# 5. IAM Role for the AGENT (Target of Hijacking)
resource "aws_iam_role" "agent_role" {
  name = "bedrock_agent_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = { Service = "bedrock.amazonaws.com" }
    }]
  })
}

# 6. Critical Policy attached to AGENT (Not EC2)
# The attacker hijacks the agent to use THIS policy.
resource "aws_iam_policy" "agent_s3_policy" {
  name = "agent_s3_policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
        Action = "s3:PutObject"
        Effect = "Allow"
        Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_agent_s3" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.agent_s3_policy.arn
}

# 7. AI Service (Bedrock Logging) - Secondary Target
resource "aws_bedrock_model_invocation_logging_configuration" "main" {
  logging_config {
    s3_config {
      bucket_name = aws_s3_bucket.ai_logs.bucket
    }
  }
}

# 8. Public S3 Bucket (The Ultimate Target)
resource "aws_s3_bucket" "ai_logs" {
  bucket = "company-ai-prompt-logs-sensitive"
  acl    = "public-read"
}
