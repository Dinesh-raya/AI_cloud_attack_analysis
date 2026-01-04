# Secure Infrastructure Example
# This configuration follows security best practices
# Expected Result: "No exploitable attack paths detected."

resource "aws_s3_bucket" "secure_training_data" {
  bucket = "secure-ml-training-data"

  tags = {
    Environment = "production"
    Compliance  = "SOC2"
  }
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "secure_block" {
  bucket = aws_s3_bucket.secure_training_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_training_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_sagemaker_notebook_instance" "secure_notebook" {
  name          = "secure-research-notebook"
  role_arn      = aws_iam_role.secure_sagemaker_role.arn
  instance_type = "ml.t3.medium"

  # SECURE: No direct internet access
  direct_internet_access = "Disabled"
  
  # SECURE: VPC-only deployment
  subnet_id       = "subnet-private-12345"
  security_groups = [aws_security_group.private_sg.id]
}

resource "aws_iam_role" "secure_sagemaker_role" {
  name = "SecureSageMakerRole"

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

# SECURE: Least privilege policy - only specific bucket access
resource "aws_iam_role_policy" "secure_policy" {
  name = "SecureSageMakerPolicy"
  role = aws_iam_role.secure_sagemaker_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.secure_training_data.arn,
          "${aws_s3_bucket.secure_training_data.arn}/*"
        ]
      }
    ]
  })
}

# SECURE: Private security group - no public ingress
resource "aws_security_group" "private_sg" {
  name        = "private-ml-sg"
  description = "Private security group for ML workloads"

  # No ingress from 0.0.0.0/0
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal VPC only
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Outbound allowed for updates
  }
}

# SECURE: Private subnet
resource "aws_subnet" "private_subnet" {
  vpc_id                  = "vpc-12345"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false  # No public IPs

  tags = {
    Name = "private-ml-subnet"
  }
}
