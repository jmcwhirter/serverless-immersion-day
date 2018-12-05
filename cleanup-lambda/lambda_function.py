import json
import boto3
import botocore
import time

def lambda_handler(event, context):
    clean_up_iam()
    clean_up_dynamo()
    clean_up_cognito()
    clean_up_apigateway()
    clean_up_kinesis()
    clean_up_lambda()
    clean_up_cloudformation()

def clean_up_iam():
    print ("IAM cleanup...")
    iam_client = boto3.client('iam')
    users = iam_client.list_users()
    for user in users['Users']:
        userName = user['UserName']
        if userName.startswith('training'):
            print (userName)
            response = iam_client.remove_user_from_group(
                GroupName='ImmersionDay_Students',
                UserName=userName
            )
            print (response)
            response = iam_client.delete_login_profile(
                UserName=userName
            )
            print (response)
            response = iam_client.delete_user(
                UserName=userName
            )
            print (response)

    policies = iam_client.list_policies(
        Scope='Local'
    )
    for policy in policies['Policies']:
        policyName = policy['PolicyName']
        if 'wild' in policyName or 'Wild' in policyName:
            # Find and delete policy versions
            policyVersions = iam_client.list_policy_versions(
                PolicyArn=policy['Arn']
            )
            for policyVersion in policyVersions['Versions']:
                if not policyVersion['IsDefaultVersion']:
                    policyVersionId = policyVersion['VersionId']
                    response = iam_client.delete_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policyVersionId
                    )
                    print (response)
            policyEntities = iam_client.list_entities_for_policy(
                PolicyArn=policy['Arn']
            )
            print (policyEntities)
            for policyEntityRole in policyEntities['PolicyRoles']:
                response = iam_client.detach_role_policy(
                    RoleName=policyEntityRole['RoleName'],
                    PolicyArn=policy['Arn']
                )
                print (response)
            # Delete policies
            response = iam_client.delete_policy(
                PolicyArn=policy['Arn']
            )

    roles = iam_client.list_roles()
    for role in roles['Roles']:
        roleName = role['RoleName']
        if 'wild' in roleName or 'Wild' in roleName:
            print (roleName)
            rolePolicies = iam_client.list_role_policies(
                RoleName=roleName
            )
            for rolePolicyName in rolePolicies['PolicyNames']:
                print (rolePolicyName)
                response = iam_client.delete_role_policy(
                    RoleName=roleName,
                    PolicyName=rolePolicyName
                )
                print (response)

            attachedPolicies = iam_client.list_attached_role_policies(
                RoleName=roleName
            )
            for attachedPolicy in attachedPolicies['AttachedPolicies']:
                print (attachedPolicy['PolicyName'])
                response = iam_client.detach_role_policy(
                    RoleName=roleName,
                    PolicyArn=attachedPolicy['PolicyArn']
                )
                print (response)

            response = iam_client.delete_role(
                RoleName=roleName
            )
            print (response)

def clean_up_cognito():
    print ("Cognito cleanup...")
    for region in boto3.session.Session().get_available_regions('cognito-identity'):
        print (region)
        cognito_client = boto3.client('cognito-identity', region_name=region)
        identityPools = cognito_client.list_identity_pools(
            MaxResults=60
        )
        for identityPool in identityPools['IdentityPools']:
            identityPoolName = identityPool['IdentityPoolName']
            if 'wild' in identityPoolName or 'Wild' in identityPoolName:
                print (identityPoolName)
                response = cognito_client.delete_identity_pool(
                    IdentityPoolId=identityPool['IdentityPoolId']
                )
                print (response)

def clean_up_dynamo():
    print ("Dynamo cleanup...")
    for region in boto3.session.Session().get_available_regions('dynamodb'):
        print (region)
        dynamo_client = boto3.client('dynamodb', region_name=region)
        dynamoTables = dynamo_client.list_tables()
        for tableName in dynamoTables['TableNames']:
            print (tableName)
            response = dynamo_client.delete_table(
                TableName=tableName
            )
            print (response)

def clean_up_apigateway():
    print ("API Gateway cleanup...")
    for region in boto3.session.Session().get_available_regions('apigateway'):
        print (region)
        apigateway_client = boto3.client('apigateway', region_name=region)
        restAPIs = apigateway_client.get_rest_apis()
        for restAPI in restAPIs['items']:
            print (restAPI['name'])
            try:
                response = apigateway_client.delete_rest_api(
                    restApiId=restAPI['id']
                )
            except botocore.exceptions.ClientError as err:
                response = err.response
                print("Failed to delete rest API:", response)
                if (response and response.get("Error", {}).get("Code") == "TooManyRequestsException"):
                    print("Continue for TooManyRequestsException exception.")
                    continue

def clean_up_kinesis():
    print ("Kinesis cleanup...")
    for region in boto3.session.Session().get_available_regions('kinesis'):
        print (region)
        kinesis_client = boto3.client('kinesis', region_name=region)
        streamNames = kinesis_client.list_streams()
        print (streamNames)
        for streamName in streamNames['StreamNames']:
            print (streamName)
            response = kinesis_client.delete_stream(
                StreamName=streamName,
                EnforceConsumerDeletion=True
            )
            time.sleep(1)
            print (response)

    for region in boto3.session.Session().get_available_regions('kinesisanalytics'):
        print (region)
        kinesisanalytics_client = boto3.client('kinesisanalytics', region_name=region)
        kinesisApps = kinesisanalytics_client.list_applications()
        # print (kinesisApps)
        for kinesisApp in kinesisApps['ApplicationSummaries']:
            appName = kinesisApp['ApplicationName']
            print (appName)
            # Get timestamp from application
            applicationDetail = kinesisanalytics_client.describe_application(
                ApplicationName=appName
            )
            # Feed in timestamp and delete app
            response = kinesisanalytics_client.delete_application(
                ApplicationName=appName,
                CreateTimestamp=applicationDetail['ApplicationDetail']['CreateTimestamp']
            )
            print (response)

def clean_up_lambda():
    print ("Lambda cleanup...")
    for region in boto3.session.Session().get_available_regions('lambda'):
        print (region)
        lambdaclient = boto3.client('lambda', region_name=region)
        functions = lambdaclient.list_functions()
        for function in functions['Functions']:
            functionArn = function['FunctionArn']
            tags = lambdaclient.list_tags(
                Resource=functionArn
            )
            if 'protected' not in tags['Tags'] or not tags['Tags']['protected']:
                functionName = function['FunctionName']
                print (functionName)
                response = lambdaclient.delete_function(
                    FunctionName=functionName
                )
                print (response)

def clean_up_cloudformation():
    print ("Cloudformation cleanup...")
    for region in boto3.session.Session().get_available_regions('cloudformation'):
        print (region)
        cloudformationclient = boto3.client('cloudformation', region_name=region)
        stacks = cloudformationclient.list_stacks()
        for stack in stacks['StackSummaries']:
            stackName = stack['StackName']
            if 'cloud9' in stackName:
                print (stackName)
                response = cloudformationclient.delete_stack(
                    StackName=stackName
                )
                print (response)
