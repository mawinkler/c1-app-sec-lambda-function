# Protect a containerized Lambda with Application Security

- [Protect a containerized Lambda with Application Security](#protect-a-containerized-lambda-with-application-security)
  - [Lab Requirements](#lab-requirements)
  - [Basic Workflow](#basic-workflow)
    - [Build the Container Image](#build-the-container-image)
    - [Publish the Image on ECR](#publish-the-image-on-ecr)
    - [Create a Lambda using our Image](#create-a-lambda-using-our-image)
    - [Prepare Application Security](#prepare-application-security)
    - [Protect the Lambda Container with C1AS](#protect-the-lambda-container-with-c1as)
  - [Creating a Demo Environment](#creating-a-demo-environment)
    - [Deploy the Stack](#deploy-the-stack)
    - [Review the Logs](#review-the-logs)
    - [Bonus](#bonus)
  - [Tear Down](#tear-down)
  - [Appendix](#appendix)
  - [Container Lambda](#container-lambda)

## Lab Requirements

I recommend you to either work in a Cloud9 environment or locally on your system.

If working locally, make sure to have an AWS CLI and Docker available.

## Basic Workflow

In this basic workflow we're going to create a Lambda which function code is inside a container image. In the second workflow afterwards we will create a fully functional demo environemnt which is protected with Application Security. First, steps first, though.

### Build the Container Image

First, git clone the lab material via

```sh
git clone https://github.com/mawinkler/c1-app-sec-lambda-function.git
cd c1-app-sec-lambda-function/container
```

Here's an example Dockerfile which we will use in this lab:

```Dockerfile
FROM public.ecr.aws/lambda/python:3.8

# Copy function code
COPY index.py ${LAMBDA_TASK_ROOT}

# Install the function's dependencies using file requirements.txt
# from your project folder.

COPY requirements.txt  .
RUN  pip3 install -r requirements.txt --target "${LAMBDA_TASK_ROOT}"

# Set the CMD to your handler (could also be done as a parameter override outside of the Dockerfile)
CMD [ "index.handler" ] 
```

It doesn't do much. Basically, it uses an AWS provided base image, copies our function code into it and deploys the required dependencies.

The function code is implemented in the `index.py` which looks like this:

```py
import json
import requests

def handler(event, context):
    print("EVENT: %s" % (event,))
    content = ""
    filename = ""

    if event.get("queryStringParameters") and 'file' in event["queryStringParameters"]:
        filename = event["queryStringParameters"]['file']

    if event.get("file"):
        filename = event.get("file")

    if filename != "":
        try:
            with open(filename, 'r') as f:
                content = f.read()
                content = content.replace('\0', '\n')
        except BaseException:
            return _403()

    BODY = """<!DOCTYPE html>
    <html><head><title>Hello World</title></head>
    <body>
    <h3>Hello World</h3>
    <form method="POST" action="" enctype="multipart/form-data">
        <input type="text" name="hello"/>
        <input type="file" name="content" />
        <input type="submit" />
    </form>
    <pre>%s</pre>
    </body>
    """ % content

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'text/html; charset=utf8'
        },
        'isBase64Encoded': False,
        'body': BODY,
    }


def _403():
    return {
        'statusCode': 403,
        'headers': {
        },
        'isBase64Encoded': False,
        'body': 'Blocked',
    }
```

As you can easily see, it will be vulnerable to illegal file access ;-)

Build and run

```sh
docker build -t hello-world:v1 .
docker run -p 9000:8080 hello-world:v1
```

To test it, run the following in a second shell

```sh
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{"file": "/etc/passwd"}'
```

Amongst others you should see the contents of the passwd file. This is obviously something we don't want in real life.

### Publish the Image on ECR

Lambda can use the image after we pushed it to the ECR. As long as we're working in the same region and account for the ECR and Lambda, this is very easy to do.

```sh
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --output text --query Account)
export AWS_REGION=eu-central-1
```

```sh
# Authenticate the Docker CLI to your Amazon ECR registry.
aws ecr get-login-password \
  --region ${AWS_REGION} | docker login \
    --username AWS \
    --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Create a repository in Amazon ECR using the create-repository command.
aws ecr create-repository \
  --repository-name hello-world \
  --image-scanning-configuration scanOnPush=true \
  --image-tag-mutability MUTABLE

# Tag & push
docker tag hello-world:latest \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/hello-world:v1
docker push \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/hello-world:v1
```

### Create a Lambda using our Image

When you deploy code as a container image to a Lambda function, the image undergoes an optimization process for running on Lambda. This process can take a few seconds, during which the function is in pending state. When the optimization process completes, the function enters the active state.

For a function in the same account as the container image in Amazon ECR, you can add `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` permissions to your Amazon ECR repository. The following shows this minimum policy:

```sh
# Define the policy
LAMBDA_PULL_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "LambdaECRImageRetrievalPolicy",
    "Effect": "Allow",
    "Principal": {
      "Service": "lambda.amazonaws.com"
    },
    "Action": [
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer"
    ]
  }]
}'

# Assign the policy to the repository
aws ecr set-repository-policy \
  --repository-name hello-world \
  --policy-text "${LAMBDA_PULL_POLICY}"
```

Output should be like this:

```json
{
    "registryId": "634503960501",
    "repositoryName": "hello-world",
    "policyText": "{\n  \"Version\" : \"2012-10-17\",\n  \"Statement\" : [ {\n    \"Sid\" : \"LambdaECRImageRetrievalPolicy\",\n    \"Effect\" : \"Allow\",\n    \"Principal\" : {\n      \"Service\" : \"lambda.amazonaws.com\"\n    },\n    \"Action\" : [ \"ecr:BatchGetImage\", \"ecr:GetDownloadUrlForLayer\" ]\n  } ]\n}"
}
```

Now, let's create the Lambda

```sh
# Create function
aws lambda create-function \
  --region ${AWS_REGION} \
  --function-name hello-world \
  --package-type Image \
  --code ImageUri=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/hello-world:latest \
  --role arn:aws:iam::${AWS_ACCOUNT_ID}:role/LambdaBasicExecutionRole
```

Doing so will create a Lambda using our container for the implementation. You could no go ahead an configure a trigger for the lambda for which you could use an API-Gateway as an example.

Do ease your life in this lab I did create a CloudFormation template doing all the necessary things for you. But first, we need to...

### Prepare Application Security

Logon to Cloud One and select the Application Security tile. Create an Application Security Group and note the group key and secret.

Within the policy of the group activate at least `Malicious Payload` and `Illegal File Access`. Either choose to `Mitigate` or `Report` for the controls.

### Protect the Lambda Container with C1AS

We as Trend do provide base images for [Python](https://gallery.ecr.aws/cloudone_application_security/lambda-python) and [Node](https://gallery.ecr.aws/cloudone_application_security/lambda-node) which have Application Security included.

Essentially, the only thing we need to do to our container image is to change the `FROM` statement in our Dockerfile to

`FROM public.ecr.aws/cloudone_application_security/lambda-python:3.7.10-9`

Then, build, tag & push giving it a new tag.

```sh
# Build
docker build -t hello-world:v2 .
```

To easily test it locally run the following:

```sh
# Adapt the following three variables
TREND_AP_KEY=<YOUR KEY>
TREND_AP_SECRET=<YOUR SECRET>
TREND_AP_HELLO_URL=<YOUR CLOUD ONE REGION>

docker run -p 9000:8080 \
  -e TREND_AP_KEY=${TREND_AP_KEY} \
  -e TREND_AP_SECRET=${TREND_AP_SECRET} \
  -e TREND_AP_READY_TIMEOUT=30 \
  -e TREND_AP_HELLO_URL=https://agents.${TREND_C1_REGION}.application.cloudone.trendmicro.com/ \
  hello-world:v2

curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d '{"file": "/etc/passwd"}'
```

```json
{"statusCode": 403, "headers": {}, "isBase64Encoded": false, "body": "Blocked"}
```

Since Application Security seems to do it's job, it's time to update our Lambda. Do this by tagging and pushing the image to ECR.

```sh
# Tag
docker tag hello-world:v2 \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/hello-world:v2

# Push
docker push \
  ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/hello-world:v2
```

We need to tell Lambda to use our new image for the hello-world function, of course.

```sh
# Update function code
aws lambda update-function-code \
  --region ${AWS_REGION} \
  --function-name hello-world \
  --image-uri ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/hello-world:v2
```

Note that we used a new tag `v2` in the steps above.

To verify that our new container is used run

```sh
aws lambda get-function \
  --region ${AWS_REGION} \
  --function-name hello-world
```

## Creating a Demo Environment

In this chapter, we're going to create a reusable demo environment which you can easily deploy and destroy ;-)

We will do this by the use of a simple CloudFormation Template. Please take a minute or two to inspect what it is doing.

The CloudFormation template(s) are inside the `cloudformation` directory.

> Note: In this chapter we're using the one called `c1as-hello-world-container.yml`.

### Deploy the Stack

To create the stack head over to your AWS console and go to the `CloudFormation` service.

- Click on `Create stack` and select `With new resources (standard)`
- Leave `Prerequisite - Prepare template` at `Template is ready`
- Select `Specify template` --> `Upload a template file`
- Click on `Choose file` and upload the provided template `c1as-hello-world-container.yml`
- Click `[Next]`
- Set a `Stack name`
- Adapt
  - `EcrImageUri`
  - `TrendApKey`
  - `TrendApSecret`
  - `TrendApReadyTimeout`
  - `TrendApHelloUrl`
- Click `[Next]`
- Check `I acknowledge that AWS CloudFormation might create IAM resources.`
- Click `[Next]`

After the stack has been created successfully the variable `ApiGatewayInvokeURL` is shown in the Outputs section of the stack.

Click on the link and after some seconds our app should open in your browser. Test the Application Security integration by appending `?file=/etc/passwd` to the URL.

### Review the Logs

Lastly, head over to `CloudWatch` and click on `Logs` --> `Log Groups`. You will find a log group with the same name as your Lambda. Click on it and have a look into the latest log stream and look for `defence-json`.

```json
2022-03-08T14:24:26.649+0000 - defence-json (lib/hooks/HookEvent.lua:192) - PID 8 - thread 140089745942080 - WARN: SensorEvent: {
    "rule_id": "1005936",
    "data_position": 15,
    "event_type": "security_engine/IPSEvent",
    "sensor_event": {
        "id": "3ace2763-2183-46ff-9de5-9e910760f18b",
        "blocked": true,
        "agent_environment_id": "864b94c6aa73d7bd110f7da4931e75860e4ce405b189e4b30f9fad0b79ec0e6c",
        "occurred_at": "2022-03-08T14:24:23.330Z",
        "host_agent_version": "4.5.0",
        "vmcode_version": "vmcode/master/843",
        "tags": [],
        "vmdata_version": "154",
        "host_agent_type": "agent-python"
    },
    "data_position_in_stream": 15,
    "payload": "GET /?file=/etc/passwd HTTP/1.1\r\naccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\naccept-language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7\r\nhost: qfswg5lewc.execute-api.eu-central-1.amazonaws.com\r\nx-amzn-trace-id: Root=1-62276711-5fe278114fc7530356f4e2fd\r\nsec-fetch-user: ?1\r\ncloudfront-is-tablet-viewer: false\r\nx-amz-cf-id: BA9z9tEXUa2QKTO9DwNsX-Tlp6lxlUNOsFBEWH0XFYr93jOzfQ6WMg==\r\ncloudfront-is-mobile-viewer: false\r\nupgrade-insecure-requests: 1\r\nsec-ch-ua-mobile: ?0\r\ncloudfront-is-smarttv-viewer: false\r\nx-forwarded-for: 87.170.29.211, 130.176.218.82\r\nsec-fetch-mode: navigate\r\nsec-ch-ua-platform: \"macOS\"\r\nsec-fetch-dest: document\r\ncookie: awsccc=eyJlIjoxLCJwIjoxLCJmIjoxLCJhIjoxLCJpIjoiZGQwOGQ4MTgtNWQyYi00OGQ5LThlODAtYjVlZjE1YmExNjg5IiwidiI6IjEifQ==\r\ncloudfront-forwarded-proto: https\r\naccept-encoding: gzip, deflate, br\r\nsec-fetch-site: none\r\ncloudfront-viewer-country: DE\r\ncloudfront-is-desktop-viewer: true\r\nvia: 2.0 09dddedbac44fa07d4af5f638358fa8a.cloudfront.net (CloudFront)\r\nx-forwarded-port: 443\r\nx-forwarded-proto: https\r\nsec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"98\", \"Google Chrome\";v=\"98\"\r\nuser-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.109 Safari/537.36\r\n\r\n",
    "transaction": {
        "transaction_uuid": "35fe9c22-0eb7-49e7-8d90-014f757906f8",
        "initiator": {
            "lambda_invocation": {
                "function_name": "hello-world-container-LambdaApiGatewayHandler-pYx3T5qKlLHy",
                "aws_request_id": "fa8707ad-2d84-4ed8-9d88-706c08660337",
                "invoked_function_arn": "arn:aws:lambda:eu-central-1:634503960501:function:hello-world-container-LambdaApiGatewayHandler-pYx3T5qKlLHy",
                "function_version": "$LATEST",
                "invoker": {
                    "api_gateway": {
                        "query_string": "file=/etc/passwd",
                        "stage": "release",
                        "amzn_trace_id": "Root=1-62276711-5fe278114fc7530356f4e2fd",
                        "headers": {
                            "host": "qfswg5lewc.execute-api.eu-central-1.amazonaws.com"
                        },
                        "path": "/",
                        "method": "GET",
                        "scheme": "https",
                        "server_port": 443,
                        "request_id": "4f42cf3b-b269-46e7-be27-d0deef849e78",
                        "remote_addr": "87.170.29.211",
                        "domain_name": "qfswg5lewc.execute-api.eu-central-1.amazonaws.com"
                    }
                }
            }
        }
    }
}
```

### Bonus

If you want to play without containers but so called .zip file archives for the code, you can easily deploy the other CloudFormation templates provided.

The app itself is basically identical, but this time the code resides directly in the template file.

There are two variants which demonstrate the use of Python 3.7 and Python 3.8.

You can have all three stacks deployed in parallel.

Lab done.

## Tear Down

There's no real need to delete everything, since Lambda is charged on usage. If you still want to clean up, head over to `CloudFormation` and delete the newly created stack.

Afterwards, go to ECR and delete the repository `hello-world`.

## Appendix

## Container Lambda

Links:

- <https://docs.aws.amazon.com/lambda/latest/dg/images-create.html>
- <https://docs.aws.amazon.com/lambda/latest/dg/configuration-images.html>

You can use an AWS provided base image or an alternative base image, such as the Application Security images :-), which we will do later in this lab.

Lambda supports images up to 10 GB in size.

To deploy a container image to Lambda, note the following requirements:

- The container image must implement the Lambda Runtime API. The AWS open-source runtime interface clients implement the API. You can add a runtime interface client to your preferred base image to make it compatible with Lambda.
- The container image must be able to run on a read-only file system. Your function code can access a writable /tmp directory with 512 MB of storage.
- The default Lambda user must be able to read all the files required to run your function code. Lambda follows security best practices by defining a default Linux user with least-privileged permissions. Verify that your application code does not rely on files that other Linux users are restricted from running.
- Lambda supports only Linux-based container images.
- Lambda provides multi-architecture base images. However, the image you build for your function must target only one of the architectures. Lambda does not support functions that use multi-architecture container images.
