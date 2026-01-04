resource "aws_instance" "waf_ec2" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"
  
  vpc_security_group_ids = [aws_security_group.waf_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.waf_profile.name

  # Vulnerability: IMDSv1 is enabled (default) which allows SSRF to steal credentials
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # This means IMDSv1 is allowed
    http_put_response_hop_limit = 1
  }
}

resource "aws_security_group" "waf_sg" {
  name = "waf-sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_instance_profile" "waf_profile" {
  name = "waf_profile"
  role = aws_iam_role.waf_role.name
}

resource "aws_iam_role" "waf_role" {
  name = "CustomWAFRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# Vulnerability: Massive S3 access
resource "aws_iam_role_policy" "exfil" {
  role = aws_iam_role.waf_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "s3:*"
      Effect = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_s3_bucket" "credit_apps" {
  bucket = "customer-credit-applications"
}
