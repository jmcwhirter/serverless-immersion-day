Package the code

`rm cleanup-lambda.zip && cd cleanup-lambda && zip cleanup-lambda.zip lambda_function.py setup.cfg && mv cleanup-lambda.zip ../ && cd ../`

Upload code and keep it public

`aws s3 cp cleanup-lambda.zip s3://serverless-immersion-day --profile=personal --acl public-read`

This should be deployed from us-east-2 [since that is where the S3 code artifact is stored](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-code.html).
