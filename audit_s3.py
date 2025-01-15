# Import required libraries
import argparse
import pandas as pd
from modules.build_client import build_client
from botocore.exceptions import ClientError
import os
from datetime import datetime

# Create argparse object and arguments
parser = argparse.ArgumentParser(description='Check for public S3 buckets in your AWS account.')
parser.add_argument('-r', '--region', type=str, required=False, default=None,
                    help='The region to evaluate S3 resources for. Defaults to the region in your AWS profile.')
parser.add_argument('-p', '--profile', type=str, required=False, default='default',
                    help='AWS credential profile. Defaults to "default".')
parser.add_argument('-b', '--bucket', type=str, action='append', required=False,
                    help='Specify a single bucket to evaluate. Defaults to evaluating all buckets.')
args = parser.parse_args()

# Initialize S3 client
s3 = build_client(args.profile, 's3', args.region)

# Functions
def get_s3_buckets():
    """Fetch the list of all S3 buckets in the account."""
    try:
        response = s3.list_buckets()
        return [bucket['Name'] for bucket in response['Buckets']]
    except ClientError as error:
        handle_client_error(error)

def get_block_public_access_rules(bucket):
    """Check public access block rules for a specific bucket."""
    try:
        response = s3.get_public_access_block(Bucket=bucket)
        config = response['PublicAccessBlockConfiguration']
        return "Enabled" if all(config.values()) else "Partially Enabled" if any(config.values()) else "Disabled"
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return "No Configuration"
        handle_client_error(error)

def get_bucket_policy(bucket):
    """Check if the bucket policy makes it public."""
    try:
        response = s3.get_bucket_policy_status(Bucket=bucket)
        return "Public" if response['PolicyStatus']['IsPublic'] else "Private"
    except ClientError as error:
        if error.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return "No Policy"
        handle_client_error(error)

def get_bucket_acl(bucket):
    """Check if the bucket ACL grants public access."""
    try:
        response = s3.get_bucket_acl(Bucket=bucket)
        for grant in response['Grants']:
            if grant.get('Grantee', {}).get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                return "Public"
        return "Private"
    except ClientError as error:
        handle_client_error(error)

def handle_client_error(error):
    """Handle AWS ClientError exceptions."""
    error_code = error.response['Error']['Code']
    if error_code in ['AccessDenied', 'UnauthorizedOperation']:
        print(f"Access Denied: {error_code}. Check IAM permissions.")
        exit(1)
    print(f"Unexpected error: {error_code}")
    exit(1)

def identify_public_buckets(buckets):
    """Evaluate buckets for public access vulnerabilities."""
    results = []
    for bucket in buckets:
        public_block = get_block_public_access_rules(bucket)
        bucket_policy = get_bucket_policy(bucket)
        bucket_acl = get_bucket_acl(bucket)
        results.append({
            "Bucket Name": bucket,
            "Public Block Enabled": public_block,
            "Bucket Policy Public": bucket_policy,
            "Bucket ACL Public": bucket_acl
        })
    return results

def save_report(results, output_path):
    """Save the results as a timestamped text report."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as report_file:
        for result in results:
            report_file.write(f"Bucket Name: {result['Bucket Name']}\n")
            report_file.write(f"  Public Block Enabled: {result['Public Block Enabled']}\n")
            report_file.write(f"  Bucket Policy Public: {result['Bucket Policy Public']}\n")
            report_file.write(f"  Bucket ACL Public: {result['Bucket ACL Public']}\n")
            report_file.write("\n")
    print(f"Report saved to: {output_path}")

# Main logic
if __name__ == '__main__':
    all_buckets = get_s3_buckets()

    # Filter for specified bucket if provided
    if args.bucket:
        specified_buckets = [bucket for bucket in args.bucket if bucket in all_buckets]
        if not specified_buckets:
            print("Specified bucket(s) not found in the account.")
            exit(1)
        all_buckets = specified_buckets

    results = identify_public_buckets(all_buckets)

    # Generate timestamped filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"./output/s3_audit_{timestamp}.txt"
    save_report(results, output_filename)
    print("S3 bucket audit completed successfully.")
