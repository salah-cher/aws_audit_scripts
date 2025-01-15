import argparse
import pandas as pd
import modules.build_client as bc
from botocore.exceptions import ClientError
import datetime

# Create argparse object and arguments
parser = argparse.ArgumentParser(description='Check for public S3 buckets in your AWS account.')
parser.add_argument('-r', '--region', action='store', type=str,
                    help='The region to evaluate S3 resources for. If not set, uses the default region specified in your profile.',
                    required=False, default=None)
parser.add_argument('-p', '--profile', action='store',
                    help='AWS credential profile to run the script under. Automatically uses "default" if no profile is specified.',
                    required=False, default='default')
parser.add_argument('-b', '--bucket', action='append',
                    help='The single bucket to evaluate. If no bucket is specified, automatically evaluates all buckets in the account.',
                    required=False)

args = parser.parse_args()

# Create required S3 clients
service = 's3'
s3 = bc.build_client(args.profile, service, args.region)

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

def identify_public_buckets(all_buckets):
    """Identify public buckets and check their security settings."""
    result_output = []

    for bucket in all_buckets:
        public_block = get_block_public_access_rules(bucket)
        bucket_policy = get_bucket_policy(bucket)
        bucket_acl = get_bucket_acl(bucket)
        encryption = get_s3_bucket_encryption(bucket)
        versioning = get_versioning(bucket)
        logging = get_logging(bucket)
        lifecycle = get_lifecycle(bucket)
        website = get_website_configuration(bucket)
        cors = get_cors_configuration(bucket)

        result_output.append(f"\nBucket Name: {bucket}")
        result_output.append(f"Public Block Enabled: {public_block}")
        result_output.append(f"Bucket Policy Public: {bucket_policy}")
        result_output.append(f"Bucket ACL Public: {bucket_acl}")
        result_output.append(f"Default Encryption: {encryption}")
        result_output.append(f"Versioning: {versioning}")
        result_output.append(f"Logging: {logging}")
        result_output.append(f"Lifecycle Policies: {lifecycle}")
        result_output.append(f"Website Hosting: {website}")
        result_output.append(f"CORS Configuration: {cors}")
        result_output.append("-" * 60)

    return "\n".join(result_output)

def create_s3_report(results_output):
    """Create and save the S3 audit report."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'./output/s3_audit_{timestamp}.txt'

    with open(filename, 'w') as f:
        f.write(results_output)
    
    print(f'Report saved to {filename}')

# Main block
all_buckets = get_s3_buckets()
results_output = identify_public_buckets(all_buckets)
create_s3_report(results_output)
print('S3 buckets evaluated successfully.')
