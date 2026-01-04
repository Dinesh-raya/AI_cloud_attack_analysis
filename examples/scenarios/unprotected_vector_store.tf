# Scenario: Vector DB exposed to the internet via direct Security Group rule
# Common in "fast prototypes"

resource "aws_opensearch_domain" "dev_vector_db" {
  domain_name    = "dev-vector-store"
  engine_version = "OpenSearch_2.5"

  cluster_config {
    instance_type = "t3.small.search"
  }

  # Vulnerability: Placed in a VPC but the Security Group allows 0.0.0.0/0
  vpc_options {
    subnet_ids         = ["subnet-12345"]
    security_group_ids = [aws_security_group.vector_sg.id]
  }
}

resource "aws_security_group" "vector_sg" {
  name        = "vector-db-public-sg"
  description = "Allows public access to vector API"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
