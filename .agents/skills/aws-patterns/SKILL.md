---
name: aws-patterns
description: AWS Lambda, S3, RDS, ECS, CDK — serverless and container patterns, IAM least privilege
metadata:
  type: skill
  triggers: ["aws", "lambda", "s3", "ecs", "cdk", "serverless", "amazon", "cloudformation"]
---

# AWS Patterns

## Lambda (Node.js)
```typescript
export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
  try {
    const body = JSON.parse(event.body ?? '{}');
    return { statusCode: 200, body: JSON.stringify({ result }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: 'Internal error' }) };
  }
};
```

## S3 presigned URL (secure upload)
```typescript
const command = new PutObjectCommand({ Bucket: 'my-bucket', Key: `uploads/${uuid()}` });
const url = await getSignedUrl(s3Client, command, { expiresIn: 300 });
```

## IAM least privilege
```json
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/uploads/*"
}
```

## CDK
```typescript
const bucket = new s3.Bucket(this, 'MyBucket', {
  versioned: true,
  encryption: s3.BucketEncryption.S3_MANAGED,
  blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
});
```

## Rules
- Never use root AWS keys — create IAM user/role with minimal permissions
- Enable CloudTrail in all regions
- S3: block public access by default
- Lambda: set memory 512MB-1GB (CPU scales with memory)
