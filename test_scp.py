import boto3
from botocore.exceptions import ClientError

def leave_organization():
    client = boto3.client('organizations')
    try:
        response = client.leave_organization()
        print("Allowed to leave the organization.")
        return "Allowed"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'AccessDeniedException' or "explicit deny in a service control policy" in error_message:
            print("Denied to leave the organization. Error: Access Denied")
            return "Denied to leave the organization. Error: Access Denied"
        else:
            print(f"An error occurred: {error_message}")
            return f"An error occurred: {error_message}"
def create_login_profile():
    client = boto3.client('iam')
    try:
        response = client.create_login_profile(
            UserName='test-user',
            Password='TestPassword123!',
            PasswordResetRequired=True
        )
        print("Allowed to create login profile.")
        return "Allowed"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'AccessDeniedException' or "explicit deny in a service control policy" in error_message:
            print("Denied to create login profile. Error: Access Denied")
            return "Denied to create login profile. Error: Access Denied"
        else:
            print(f"An error occurred: {error_message}")
            return f"An error occurred: {error_message}"
def create_access_key():
    client = boto3.client('iam')
    try:
        response = client.create_access_key(
            UserName='root'
        )
        print("Allowed to create access key.")
        return "Allowed"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'AccessDeniedException' or "explicit deny in a service control policy" in error_message:
            print("Denied to create access key. Error: Access Denied")
            return "Denied to create access key. Error: Access Denied"
        else:
            print(f"An error occurred: {error_message}")
            return f"An error occurred: {error_message}"
def delete_s3_bucket():
    client = boto3.client('s3')
    try:
        response = client.delete_bucket(
            Bucket='bucket-name'
        )
        print("Allowed to delete S3 bucket.")
        return "Allowed"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'AccessDeniedException' or "explicit deny in a service control policy" in error_message:
            print("Denied to delete S3 bucket. Error: Access Denied")
            return "Denied to delete S3 bucket. Error: Access Denied"
        else:
            print(f"An error occurred: {error_message}")
            return f"An error occurred: {error_message}"
def stop_cloudtrail_logging():
    client = boto3.client('cloudtrail')
    try:
        response = client.stop_logging(
            Name='trail-name'
        )
        print("Allowed to stop CloudTrail logging.")
        return "Allowed"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'AccessDeniedException' or "explicit deny in a service control policy" in error_message:
            print("Denied to stop CloudTrail logging. Error: Access Denied")
            return "Denied to stop CloudTrail logging. Error: Access Denied"
        else:
            print(f"An error occurred: {error_message}")
            return f"An error occurred: {error_message}"

def delete_config_recorder():
    client = boto3.client('config')
    try:
        response = client.delete_configuration_recorder(
            ConfigurationRecorderName='default'
        )
        print("Allowed to delete configuration recorder.")
        return "Allowed"
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'AccessDeniedException' or "explicit deny in a service control policy" in error_message:
            print("Denied to delete configuration recorder. Error: Access Denied")
            return "Denied to delete configuration recorder. Error: Access Denied"
        else:
             print(f"An error occurred: {error_message}")
             return f"An error occurred: {error_message}"

def main():
    # Test each policy
    print("Testing leave organization policy:")
    leave_organization_result = leave_organization()
    print(f"Result: {leave_organization_result}")
    print("Testing create login profile policy:")
    create_login_profile_result = create_login_profile()
    print(f"Result: {create_login_profile_result}")
    print("Testing create access key policy:")
    create_access_key_result = create_access_key()
    print(f"Result: {create_access_key_result}")
    print("Testing delete S3 bucket policy:")
    delete_s3_bucket_result = delete_s3_bucket()
    print(f"Result: {delete_s3_bucket_result}")
    print("Testing stop CloudTrail logging policy:")
    stop_cloudtrail_logging_result = stop_cloudtrail_logging()
    print(f"Result: {stop_cloudtrail_logging_result}")
    print("Testing delete configuration recorder policy:")
    delete_config_recorder_result = delete_config_recorder()
    print(f"Result: {delete_config_recorder_result}")

if __name__ == "__main__":
    main()