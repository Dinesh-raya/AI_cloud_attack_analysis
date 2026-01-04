resource "aws_lambda_function" "hr_assistant_tool" {
  function_name = "hr-data-tool"
  role          = aws_iam_role.hr_tool_role.arn
  handler       = "index.handler"
  runtime       = "python3.10"
}

resource "aws_iam_role" "hr_tool_role" {
  name = "HRAssistantToolRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# Vulnerability: Tool used by AI assistant has access to the entire HR database
resource "aws_iam_role_policy" "hr_access" {
  name = "HRFullAccess"
  role = aws_iam_role.hr_tool_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "dynamodb:*"
      Effect = "Allow"
      Resource = aws_dynamodb_table.hr_table.arn
    }]
  })
}

resource "aws_dynamodb_table" "hr_table" {
  name           = "EmployeeRecords"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "EmployeeID"
  attribute {
    name = "EmployeeID"
    type = "S"
  }
}
