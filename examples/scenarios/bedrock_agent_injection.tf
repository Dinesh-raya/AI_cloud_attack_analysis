resource "aws_bedrock_agent" "customer_support" {
  agent_name                  = "support-agent"
  agent_resource_role_arn     = aws_iam_role.agent_role.arn
  foundation_model            = "anthropic.claude-v2"
  instruction                 = "You are a helpful support agent. Use your tools to help customers."
}

resource "aws_iam_role" "agent_role" {
  name = "BedrockAgentRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "bedrock.amazonaws.com" }
    }]
  })
}

resource "aws_lambda_function" "agent_tool" {
  filename      = "tool.zip"
  function_name = "support-tool"
  role          = aws_iam_role.tool_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"
}

resource "aws_iam_role" "tool_role" {
  name = "AgentToolRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

# The Vulnerability: Tool has access to sensitive prompt logs
resource "aws_iam_policy" "dump_policy" {
  name = "ExfiltrationPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
      Effect = "Allow"
      Resource = "*" # Over-permissive
    }]
  })
}

resource "aws_iam_role_policy_attachment" "tool_attach" {
  role       = aws_iam_role.tool_role.name
  policy_arn = aws_iam_policy.dump_policy.arn
}
