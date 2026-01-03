import unittest
from cloud_attack_analysis.models import Resource

class TestModels(unittest.TestCase):
    def test_resource_creation(self):
        r = Resource(id="aws_s3_bucket.test", type="aws_s3_bucket", name="test", attributes={"bucket": "foo"})
        self.assertEqual(r.id, "aws_s3_bucket.test")
        self.assertFalse(r.is_ai_service)

    def test_ai_detection(self):
        r = Resource(id="aws_bedrock.test", type="aws_bedrock_model_invocation_logging_configuration", name="test", attributes={})
        self.assertTrue(r.is_ai_service)

if __name__ == '__main__':
    unittest.main()
