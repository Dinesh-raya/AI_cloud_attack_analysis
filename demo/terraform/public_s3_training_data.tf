# Demo Scenario: Public S3 Training Data Bucket
# Risk: AI training data exposed to the internet

resource "aws_s3_bucket" "training_data" {
  bucket = "company-llm-training-data"

  tags = {
    Purpose     = "LLM Fine-tuning Dataset"
    Sensitivity = "Confidential"
  }
}

# VULNERABILITY: Public read access to training data
resource "aws_s3_bucket_policy" "training_public" {
  bucket = aws_s3_bucket.training_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicReadForTrainingData"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:ListBucket"]
      Resource  = [
        aws_s3_bucket.training_data.arn,
        "${aws_s3_bucket.training_data.arn}/*"
      ]
    }]
  })
}

# VULNERABILITY: No encryption configured
resource "aws_s3_bucket_versioning" "training_versioning" {
  bucket = aws_s3_bucket.training_data.id
  versioning_configuration {
    status = "Disabled"
  }
}
