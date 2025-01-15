# aws_audit_scripts
Scripts to help with auditing your AWS environment.

## Initial Configuration
These scripts assume that you already have working access keys configured to your AWS account. You can find details on how to configure your access keys for CLI use here: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html

While your profile is checked for credentials, you can manually specify the region and named profile to use in each script, ensuring that you can use values outside of your `~/.aws/config` file to run the scripts.

## Individual Scripts

### audit_s3.py
This script checks all of the S3 buckets in the account your access keys are configured to access. It validates:
- Whether any Public Access Block settings are configured to prevent public access for buckets
- Whether any bucket ACLs are allowing public access to the bucket
- Whether any bucket policies are allowing public access to the bucket

Once the validation is complete, a CSV file is created in the `output` folder that outlines where public access was discovered across the account's buckets.

Currently, the script only checks S3 buckets of one account. All S3 buckets of the account are checked unless the `-b` argument is used to specify a bucket. At the moment, only one bucket can be specified.

The script assumes that your configured IAM user has the correct IAM permissions to access S3 buckets. The required actions are listed below, and a full list of actions can be found here: https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazons3.html

Required actions/ permissions:
GetBucketAcl
GetBucketPolicyStatus
GetBucketPublicAccessBlock
HeadBucket

#### Usage
Execute `python audit_s3.py` from the cloned directory. Adding the `-h` argument will give help details.

### audit_rds.py
This script has multiple sets of checks it can run against RDS instances (Backups, Security, Monitoring). It validates:
- Backup/ availability settings, such as how long backups are retained for and whether read replicas/ mutli-AZ are in use
- Security settings, such as deletion protection, public accessibility, security groups in use, storage encryption, etc.
- Monitoring settings, such as the monitoring interval and performance insights

Once the validation is complete, a CSV file is created in the `output` folder that outlines RDS findings.

Currently, the script only checks RDS instances of one account. All RDS instances of the account are checked unless the `-i` argument is used to specify an instance. At the moment, only one instance can be specified, and the friendly instance name (rather than instance ID) must be used.

The script assumes that your configured IAM user has the correct IAM permissions to access RDS instances. The required actions are listed below, and a full list of actions can be found here: https://docs.aws.amazon.com/IAM/latest/UserGuide/list_amazonrds.html

Required actions/ permissions:
DescribeDBInstances

#### Usage
Execute `python audit_rds.py` from the cloned directory. Adding the `-h` argument will give help details.

### audit_vpc.py

This script audits your AWS VPC configurations, including flow logs, Internet Gateway (IGW), subnets, and route tables. It generates both text and HTML reports with detailed information about your VPCs.

## Features

- Checks if subnets auto-assign public IPs
- Evaluates if flow logs are enabled for VPCs
- Verifies if an Internet Gateway (IGW) is attached to the VPC and if the route tables are configured correctly
- Includes the type of subnets (public or private) in the report
- Verifies that each subnet has an associated route table
- Checks that the route table for public subnets has a route to the internet gateway (0.0.0.0/0)
- Ensures that the route table for private subnets has a route to the NAT gateway for outbound internet access
- Generates both text and HTML reports with timestamps

## Usage

1. Run the script:
    ```bash
    python audit_vpc.py -r <region> -p <profile> -v <vpc_id>
    ```

    - `-r` or `--region`: The region to evaluate VPC resources for. If not set, uses the default region specified in your profile.
    - `-p` or `--profile`: AWS credential profile to run the script under. Automatically uses "default" if no profile is specified.
    - `-v` or `--vpc`: The ID of the single VPC to evaluate. If no VPC is specified, automatically evaluates all VPCs in the account.

2. The script will generate both text and HTML reports in the `./output` directory with timestamps.

## Example

```bash
python audit_vpc.py -r us-east-1 -p default -v vpc-12345678
```
This will generate the following files in the ./output directory:

vpc_audit_report_<timestamp>.txt
vpc_audit_report_<timestamp>.html
