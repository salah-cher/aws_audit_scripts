### CHANGELOG

#### [Unreleased]

##### Added
- Initial script to check VPC configurations in AWS, including flow logs, IGW, and subnets.
- Function to evaluate if subnets auto-assign public IPs.
- Function to evaluate if flow logs are enabled for VPCs.
- Function to evaluate if an Internet Gateway (IGW) is attached to the VPC and if the route tables are configured correctly.
- Function to generate a text report of the VPC audit.
- Function to generate an HTML report of the VPC audit.
- Function to include the type of subnets (public or private) in the report.
- Timestamp (date_HH:MM:SS) added to the generated report and HTML page filenames.
- Check to verify that each subnet has an associated route table.
- Check to verify that the route table for public subnets has a route to the internet gateway (0.0.0.0/0).
- Check to ensure that the route table for private subnets has a route to the NAT gateway for outbound internet access.

##### Changed
- Updated the script to use `pandas.concat` instead of the deprecated `append` method.
- Improved the output format of the report to be more readable and structured.

##### Fixed
- Resolved `AttributeError` caused by the deprecated `append` method in pandas.
