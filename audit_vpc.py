import argparse
import pandas as pd
import boto3
from botocore.exceptions import ClientError
from datetime import datetime

# Create argparse object and arguments
parser = argparse.ArgumentParser(description='Check for VPC configurations in your AWS account.')
parser.add_argument('-r', '--region', action='store', type=str,
                    help='The region to evaluate VPC resources for. If not set, uses the default region specified in your profile.',
                    required=False, default=None)
parser.add_argument('-p', '--profile', action='store',
                    help='AWS credential profile to run the script under. Automatically uses "default" if no profile is specified.',
                    required=False, default='default')
parser.add_argument('-v', '--vpc', action='append',
                    help='The ID of the single VPC to evaluate. DOES NOT CURRENTLY SUPPORT USING VPC NAME. If no VPC is specified, automatically evaluates all VPCs in the account.',
                    required=False)

args = parser.parse_args()

# Create required EC2 client to gather VPC data, specifying region
session = boto3.Session(profile_name=args.profile, region_name=args.region)
ec2 = session.client('ec2')

# Begin defining functions
def get_vpcs():
    # Gathers IDs of all VPCs in the specified region
    vpc_ids = []

    try:
        vpc = ec2.describe_vpcs()

    except ClientError as error:
        error = error.response['Error']['Code']
        if error == 'InvalidClientTokenId':
            print("Error: Invalid Client Token ID. Validate that the token is valid.")
            exit(1)
        elif error == 'AccessDenied' or error == 'UnauthorizedOperation':
            print("Error: Access Denied. See README.md for IAM permissions required to execute this script.")
            exit(2)

    # Remove unnecessary keys
    vpc = vpc['Vpcs']

    # Grabs the VPC IDs to be used in next steps
    for value in vpc:
        vpc_ids.append(value['VpcId'])

    # If no VPC is specified in cmd line arguments, evaluate all VPCs in the region
    if args.vpc is None:
        print('No VPC specified; evaluating all VPCs in the current region.')
        print('Discovered VPCs: ' + str(vpc_ids).strip('[]'))
        return vpc_ids

    # If VPC is specified, check that VPC exists and exit if not
    elif args.vpc:
        # Get string of VPC name specified in cmd line argument
        vpc_specified = args.vpc[0]  # This only works while only one argument is passed in

        if vpc_specified in vpc_ids:
            return args.vpc

        elif vpc_specified not in vpc_ids:
            print('ERROR: Specified VPC does not exist in the current AWS account or Region.')
            exit(1)

def gather_subnets(vpc_ids):
    # Gather all subnets from specified VPC(s)
    vpc_subnet_dict = {}

    for vpc in vpc_ids:
        subnets = ec2.describe_subnets(Filters=[
            {
                'Name': 'vpc-id',
                'Values': [
                    vpc,
                ],
            },
        ],
        )

        # Remove unnecessary keys
        subnets = subnets['Subnets']

        # Map subnets discovered for the iterated VPC to vpc_subnet_dict variable
        for dict in subnets:
            vpc_subnet_dict[str(vpc)] = subnets

    return vpc_subnet_dict

def eval_auto_assign_public_subnets(subnet):
    # Evaluate discovered subnets for auto-assign public IP setting
    # This is currently called through a loop in a later function, meaning we don't need a permanent assignment for this function
    if subnet['MapPublicIpOnLaunch'] == True:
        auto_public_ip = True

    elif subnet['MapPublicIpOnLaunch'] == False:
        auto_public_ip = False

    return auto_public_ip

def eval_flow_logs(vpc):
    # Evaluates current VPC to determine if flow logs are enabled. If logs are enabled, returns their storage location.
    flow_logs = ec2.describe_flow_logs(Filters=[
        {
            'Name': 'resource-id',
            'Values': [
                vpc,
            ],
        },
    ],
    )

    # Remove unnecessary keys
    flow_logs = flow_logs['FlowLogs']

    # If flow log is inactive, flow_logs['FlowLogs'] returns an empty list
    if flow_logs:
        flow_log_active = flow_logs[0]['FlowLogStatus']
        flow_log_dest = flow_logs[0]['LogDestination']
    elif not flow_logs:
        flow_log_active = 'INACTIVE'
        flow_log_dest = 'N/A'

    return flow_log_active, flow_log_dest

def eval_igw(vpc_id):
    # Evaluates if an Internet Gateway (IGW) is attached to the VPC and if the route tables are configured correctly
    igw_attached = False
    route_to_igw = False

    # Check if IGW is attached
    igws = ec2.describe_internet_gateways(Filters=[
        {
            'Name': 'attachment.vpc-id',
            'Values': [vpc_id]
        }
    ])
    if igws['InternetGateways']:
        igw_attached = True

    # Check route tables for routes to IGW
    route_tables = ec2.describe_route_tables(Filters=[
        {
            'Name': 'vpc-id',
            'Values': [vpc_id]
        }
    ])
    for route_table in route_tables['RouteTables']:
        for route in route_table['Routes']:
            if route.get('GatewayId') and route['GatewayId'].startswith('igw-'):
                route_to_igw = True
                break

    return igw_attached, route_to_igw

def eval_subnet_type(subnet):
    # Evaluates the type of subnet (public or private) based on its route table configuration
    subnet_id = subnet['SubnetId']
    
    route_tables = ec2.describe_route_tables(Filters=[
        {
            'Name': 'association.subnet-id',
            'Values': [subnet_id]
        }
    ])
    
    for route_table in route_tables['RouteTables']:
        for route in route_table['Routes']:
            if route.get('GatewayId') and route['GatewayId'].startswith('igw-'):
                return "Public"
    
    return "Private"

def eval_subnet_route_table_association(subnet):
    # Evaluates if a subnet has an associated route table
    subnet_id = subnet['SubnetId']
    
    route_tables = ec2.describe_route_tables(Filters=[
        {
            'Name': 'association.subnet-id',
            'Values': [subnet_id]
        }
    ])
    
    if route_tables['RouteTables']:
        return True
    
    return False

def eval_public_subnet_route_to_igw(subnet):
    # Evaluates if a public subnet's route table has a route to the internet gateway (0.0.0.0/0)
    subnet_id = subnet['SubnetId']
    
    route_tables = ec2.describe_route_tables(Filters=[
        {
            'Name': 'association.subnet-id',
            'Values': [subnet_id]
        }
    ])
    
    for route_table in route_tables['RouteTables']:
        for route in route_table['Routes']:
            if route.get('DestinationCidrBlock') == '0.0.0.0/0' and route.get('GatewayId') and route['GatewayId'].startswith('igw-'):
                return True
    
    return False

def eval_private_subnet_route_to_nat(subnet):
    # Evaluates if a private subnet's route table has a route to the NAT gateway (0.0.0.0/0)
    subnet_id = subnet['SubnetId']
    
    route_tables = ec2.describe_route_tables(Filters=[
        {
            'Name': 'association.subnet-id',
            'Values': [subnet_id]
        }
    ])
    
    for route_table in route_tables['RouteTables']:
        for route in route_table['Routes']:
            if route.get('DestinationCidrBlock') == '0.0.0.0/0' and route.get('NatGatewayId'):
                return True
    
    return False

def populate_report(vpc_subnet_dict):
    report_lines = []

    for vpc in vpc_subnet_dict.values():
        vpc_id = vpc[0]['VpcId']
        flow_log_active, flow_log_dest = eval_flow_logs(vpc_id)
        igw_attached, route_to_igw = eval_igw(vpc_id)

        report_lines.append(f"VPC ID: {vpc_id}")
        report_lines.append(f"  Flow Logs Active: {flow_log_active}")
        report_lines.append(f"  Flow Logs Location: {flow_log_dest}")
        report_lines.append(f"  IGW Attached: {igw_attached}")
        report_lines.append(f"  Route to IGW: {route_to_igw}")

        for subnet in vpc:
            auto_public_ip = eval_auto_assign_public_subnets(subnet)
            subnet_id = subnet['SubnetId']
            subnet_type = eval_subnet_type(subnet)
            route_table_association = eval_subnet_route_table_association(subnet)
            route_to_igw = eval_public_subnet_route_to_igw(subnet) if subnet_type == "Public" else "N/A"
            route_to_nat = eval_private_subnet_route_to_nat(subnet) if subnet_type == "Private" else "N/A"

            report_lines.append(f"  Subnet ID: {subnet_id}")
            report_lines.append(f"      Subnet Assigns Public IP: {auto_public_ip}")
            report_lines.append(f"      Subnet Type: {subnet_type}")
            report_lines.append(f"      Route Table Associated: {route_table_association}")
            report_lines.append(f"      Route to IGW (0.0.0.0/0): {route_to_igw}")
            report_lines.append(f"      Route to NAT Gateway (0.0.0.0/0): {route_to_nat}")

    return "\n".join(report_lines)

def create_vpc_report(report_content):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    file_path = f'./output/vpc_audit_report_{timestamp}.txt'
    with open(file_path, 'w') as f:
         f.write(report_content)
    print(f'Text report generated: {file_path}')


def create_vpc_html_report(report_content):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
    file_path = f'./output/vpc_audit_report_{timestamp}.html'
    html_content = f"""
    <html>
    <head>
        <title>VPC Audit Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            .vpc {{ margin-bottom: 20px; }}
            .subnet {{ margin-left: 20px; }}
        </style>
    </head>
    <body>
        <h1>VPC Audit Report</h1>
        <p>Generated on: {timestamp}</p>
        <pre>{report_content}</pre>
    </body>
    </html>
    """
    with open(file_path, 'w') as f:
        f.write(html_content)
    print(f'HTML report generated: {file_path}')



# Main block
vpc_ids = get_vpcs()
vpc_subnet_dict = gather_subnets(vpc_ids)
report_content = populate_report(vpc_subnet_dict)
create_vpc_report(report_content)
create_vpc_html_report(report_content)
print('VPC(s) evaluated successfully. Output files are located in the ./output directory with timestamps.')
