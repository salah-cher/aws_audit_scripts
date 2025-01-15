### CHANGELOG

#### [Unreleased]

##### Added
- Initial script to check VPC configurations in AWS, including flow logs, IGW, and subnets.
- Function to evaluate if subnets auto-assign public IPs.
- Function to evaluate if flow logs are enabled for VPCs.
- Function to evaluate if an Internet Gateway (IGW) is attached to the VPC and if the route tables are configured correctly.
- Function to generate a text report of the VPC audit.

##### Changed
- Updated the script to use `pandas.concat` instead of the deprecated `append` method.
- Improved the output format of the report to be more readable and structured.
- Added functionality to generate an HTML report in addition to the text report.
- Included the type of subnets (public or private) in the report.
- Added a timestamp (date_HH:MM:SS) to the generated report and HTML page filenames.

##### Fixed
- Resolved `AttributeError` caused by the deprecated `append` method in pandas.
