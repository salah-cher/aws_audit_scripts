import boto3
from botocore.exceptions import ProfileNotFound, NoCredentialsError, NoRegionError

def build_client(profile, service, region=None):
    """
    Builds a Boto3 client to connect to AWS based on the provided profile, service, and region.
    If no region is specified, it uses the default region from the profile configuration.
    """
    try:
        # Initialize a session using the specified profile
        session = boto3.Session(profile_name=profile)

        # If region is not specified, use the session's default region
        if region is None:
            region = session.region_name
            if region is None:
                raise NoRegionError

        # Create the client for the specified service and region
        client = session.client(service_name=service, region_name=region)
        return client

    except ProfileNotFound:
        print(f"Error: The AWS profile '{profile}' was not found. Please check your AWS configuration.")
        exit(1)
    except NoCredentialsError:
        print("Error: AWS credentials not found. Ensure your ~/.aws/credentials file is set up correctly.")
        exit(2)
    except NoRegionError:
        print("Error: No region specified. Please provide a region or configure a default region in your AWS profile.")
        exit(3)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        exit(4)

