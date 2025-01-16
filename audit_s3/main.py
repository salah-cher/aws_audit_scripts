import argparse
import os
import pandas as pd
import modules.build_client as bc
from botocore.exceptions import ClientError
import json
from checks import *
from datetime import datetime

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
def get_s3_buckets(args):
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

def main():
    # Load the JSON configuration file
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(config_path, 'r') as config_file:
        checks = json.load(config_file)

    # Get the list of buckets
    buckets = get_s3_buckets(args)  # Pass 'args' to get_s3_buckets

    # Prepare output file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_path = os.path.join(os.path.dirname(__file__), 'output')
    os.makedirs(output_path, exist_ok=True)
    output_file = os.path.join(output_path, f's3_audit_{timestamp}.txt')

    # Start evaluating buckets
    results = []

    for bucket in buckets:
        print(f"Evaluating bucket: {bucket}")
        bucket_results = [f"Bucket Name: {bucket}"]

        for func_name, check_name in checks.items():
            try:
                # Dynamically call the function from checks module
                check_function = globals()[func_name]
                result = check_function(bucket)
                bucket_results.append(f"  {check_name}: {result}")
            except Exception as e:
                bucket_results.append(f"  {check_name}: Error - {e}")

        results.append("\n".join(bucket_results))

    # Write results to file
    with open(output_file, 'w') as f:
        f.write("\n\n".join(results))

    print(f"Report saved to {output_file}")
    print("S3 buckets evaluated successfully.")

if __name__ == "__main__":
    main()
