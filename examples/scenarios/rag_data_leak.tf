resource "aws_instance" "rag_frontend" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.web_sg.id]
  # Target for SSRF: OpenSearch
}

resource "aws_security_group" "web_sg" {
  name        = "rag-web-sg"
  description = "Allows public access to RAG UI"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_opensearch_domain" "vector_db" {
  domain_name           = "company-knowledge-base"
  engine_version        = "OpenSearch_2.5"

  # Vulnerability: Domain is in a VPC, but has a permissive access policy 
  # allowing any principal from within the VPC (or certain roles)
  cluster_config {
    instance_type = "t3.small.search"
  }

  access_policies = <<POL
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:us-east-1:123456789012:domain/company-knowledge-base/*"
    }
  ]
}
POL
}
