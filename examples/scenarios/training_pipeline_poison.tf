resource "aws_s3_bucket" "training_data" {
  bucket = "ai-training-data-public"
}

# Vulnerability: Publicly writable bucket used as trigger for training
resource "aws_s3_bucket_policy" "public_write" {
  bucket = aws_s3_bucket.training_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.training_data.arn}/*"
    }]
  })
}

resource "aws_codebuild_project" "trainer" {
  name          = "model-trainer-job"
  service_role  = aws_iam_role.codebuild_role.arn

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:5.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true
  }

  source {
    type            = "S3"
    location        = "${aws_s3_bucket.training_data.bucket}/buildspec.yml"
  }
}

resource "aws_iam_role" "codebuild_role" {
  name = "CodeBuildTrainingRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cb_admin" {
  role       = aws_iam_role.codebuild_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
