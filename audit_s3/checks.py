import argparse
import boto3  # Add this line to import boto3
import botocore
import pandas as pd
import modules.build_client as bc
from botocore.exceptions import ClientError
import datetime

# Create argparse object and arguments

# Create required S3 clients
service = 's3'
s3 = boto3.client('s3')
#s3 = bc.build_client(args.profile, service, args.region)

# Define function to handle ClientError
def handle_client_error(error):
    """Handle ClientError and print relevant error message."""
    error_code = error.response['Error']['Code']
    if error_code == 'InvalidClientTokenId':
        print("Error: Invalid Client Token ID. Validate that the token is valid.")
        exit(1)
    elif error_code == 'AccessDenied' or error_code == 'UnauthorizedOperation':
        print("Error: Access Denied. See README.md for IAM permissions required to execute this script.")
        exit(2)
    else:
        print(f"Error: {error_code}")
        exit(3)

# Begin defining functions
def get_s3_buckets():
    """Gather names of all S3 buckets in the account."""
    bucket_names = []
    try:
        buckets = s3.list_buckets()
    except ClientError as error:
        handle_client_error(error)

    buckets = buckets['Buckets']

    for name in buckets:
        bucket_names.append(name['Name'])

    if args.bucket is None:
        print('No bucket specified; evaluating all buckets in the account.')
        return bucket_names
    elif args.bucket:
        bucket_specified = args.bucket[0]
        if bucket_specified in bucket_names:
            return args.bucket
        else:
            print('ERROR: Specified bucket does not exist in the current AWS account.')
            exit(3)

def get_block_public_access_rules(bucket):
    """Checks for public access block rules for all discovered buckets."""
    try:
        block = s3.get_public_access_block(Bucket=bucket)
        block = block['PublicAccessBlockConfiguration']
        values = block.values()

        if all(values) == True:
            return "Enabled"
        elif any(result == True for result in values):
            return "Partially Enabled"
        else:
            return "Not Enabled"
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return "Not Configured"
        handle_client_error(error)

def get_bucket_policy(bucket):
    """Check if the bucket has a public bucket policy."""
    try:
        response = s3.get_bucket_policy_status(Bucket=bucket)
        policy_status = response['PolicyStatus']['IsPublic']
        return "Public" if policy_status else "Private"
    except ClientError as policy_error:
        if policy_error.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return "No bucket policy"
        handle_client_error(policy_error)

def get_bucket_acl(bucket):
    """Checks for bucket ACLs that make the bucket public."""
    try:
        bucket_acl = s3.get_bucket_acl(Bucket=bucket)
        bucket_acl = bucket_acl['Grants']
        
        for entry in bucket_acl:
            try:
                if entry['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    return "Public"
            except KeyError:
                continue
        return "Private"
    except ClientError as error:
        handle_client_error(error)

def get_s3_bucket_encryption(bucket):
    """Check for bucket encryption settings."""
    try:
        encryption = s3.get_bucket_encryption(Bucket=bucket)
        if 'ServerSideEncryptionConfiguration' in encryption:
            return "Enabled"
        else:
            return "Not Enabled"
    except ClientError as error:
        if error.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return "Not Enabled"
        handle_client_error(error)

def get_versioning(bucket):
    """Check if bucket versioning is enabled."""
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket)
        status = versioning.get('Status', 'Suspended')
        return status if status != 'Suspended' else "Not Enabled"
    except ClientError as error:
        handle_client_error(error)

def get_logging(bucket):
    """Check if logging is enabled for the bucket."""
    try:
        logging = s3.get_bucket_logging(Bucket=bucket)
        if logging.get('LoggingEnabled'):
            return "Enabled"
        else:
            return "Not Enabled"
    except ClientError as error:
        handle_client_error(error)

def get_lifecycle(bucket):
    """Check if lifecycle policies are configured."""
    try:
        lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket)
        if 'Rules' in lifecycle and lifecycle['Rules']:
            return "Configured"
        else:
            return "Not Configured"
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchLifecycleConfiguration':
            return "Not Configured"
        handle_client_error(error)

def get_website_configuration(bucket):
    """Check if website hosting is enabled."""
    try:
        website = s3.get_bucket_website(Bucket=bucket)
        return "Enabled"
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchWebsiteConfiguration':
            return "Not Enabled"
        handle_client_error(error)

def get_cors_configuration(bucket):
    """Check if CORS is configured for the bucket."""
    try:
        cors = s3.get_bucket_cors(Bucket=bucket)
        if cors.get('CORSRules'):
            return "Configured"
        else:
            return "Not Configured"
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchCORSConfiguration':
            return "Not Configured"
        handle_client_error(error)

def check_mfa_delete(bucket):
    """
    Checks if MFA Delete is enabled for the specified bucket.
    
    Args:
        bucket_name (str): The name of the S3 bucket.

    Returns:
        str: "Enabled" if MFA Delete is active, otherwise "Disabled".
    """
    try:
        response = s3.get_bucket_versioning(Bucket=bucket)
        mfa_status = response.get('MFADelete', 'Disabled')
        return mfa_status
    except ClientError as e:
        return f"Error checking MFA Delete: {e.response['Error']['Message']}"

def check_object_lock(bucket):
    """
    Checks if Object Lock is enabled for an S3 bucket.
    
    Args:
        bucket (str): Name of the S3 bucket.

    Returns:
        str: "Enabled" if Object Lock is active, "Not Configured" otherwise.
    """
    s3 = boto3.client('s3')

    try:
        response = s3.get_object_lock_configuration(Bucket=bucket)
        lock_config = response.get('ObjectLockConfiguration', {})
        
        if lock_config.get('ObjectLockEnabled') == 'Enabled':
            return "Enabled"
        else:
            return "Not Configured"
    except ClientError as e:
        if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
            return "Not Configured"
        elif e.response['Error']['Code'] == 'AccessDenied':
            return "Access Denied"
        else:
            return f"Error: {e.response['Error']['Message']}"

def check_public_objects(bucket):
    """
    Checks if any objects in the bucket are publicly accessible.

    Args:
        bucket (str): Name of the S3 bucket.

    Returns:
        str: "No public objects" if all objects are private,
             "Public objects detected" if one or more objects are public,
             or an error message if an issue occurs.
    """
    s3 = boto3.client('s3')

    try:
        # List objects in the bucket
        response = s3.list_objects_v2(Bucket=bucket)
        if 'Contents' not in response:
            return "No objects in bucket"

        for obj in response['Contents']:
            object_key = obj['Key']

            # Get object ACL
            acl_response = s3.get_object_acl(Bucket=bucket, Key=object_key)
            for grant in acl_response.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')

                # Check for public access
                if grantee.get('Type') == 'Group' and \
                   grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' and \
                   permission in ['READ', 'FULL_CONTROL']:
                    return "Public objects detected"

        return "No public objects"

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            return "Access Denied"
        else:
            return f"Error: {e.response['Error']['Message']}"



