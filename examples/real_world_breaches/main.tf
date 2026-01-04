# SHADOWRAY ATTACK SIMULATION
# Demonstrates: Internet -> Ray Head Node (EC2) -> Worker Role -> S3 (Training Data)

provider "aws" {
  region = "us-west-2"
}

# 1. Unauthenticated Ray Dashboard (Public)
resource "aws_instance" "ray_head_node" {
  ami           = "ami-ray-ai-image"
  instance_type = "p3.2xlarge"
  vpc_security_group_ids = [aws_security_group.ray_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ray_profile.name
  
  tags = {
    Name = "Ray-AI-Cluster-Head"
    Workload = "AI-Training"
  }
}

# 2. Misconfigured SG (Port 8265 open to world)
resource "aws_security_group" "ray_sg" {
  name        = "ray_dashboard_sg"
  description = "Allow Ray Dashboard Access"

  ingress {
    from_port   = 8265
    to_port     = 8265
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Also standard SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 3. High Privilege Role for "Workers" (Abused via Head Node)
resource "aws_iam_role" "ray_worker_role" {
  name = "ray_worker_role"
  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": { "Service": "ec2.amazonaws.com" }
        }
    ]
}
EOF
}

resource "aws_iam_instance_profile" "ray_profile" {
  name = "ray_profile"
  role = aws_iam_role.ray_worker_role.name
}

# 4. Access to Sensitive Training Data
resource "aws_iam_policy" "ray_data_access" {
  name = "ray_data_access"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "s3:*",
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach_ray_data" {
  role       = aws_iam_role.ray_worker_role.name
  policy_arn = aws_iam_policy.ray_data_access.arn
}

# 5. The Valid Target (S3 Bucket)
resource "aws_s3_bucket" "training_data" {
  bucket = "company-sensitive-training-data-v1"
  acl    = "private"
}
