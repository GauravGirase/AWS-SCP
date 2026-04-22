import boto3
import json
import os
import configparser


# Initialize a session using Amazon Organizations
client = boto3.client('organizations')

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

# Define the path to the policies folder
policies_folder_path = os.path.join(os.path.dirname(__file__), config['PATHS']['policies_folder_path'])

# Create a dictionary to map OU IDs to their respective policy files
policy_dict = json.loads(config['SCOPES']['policy_dict'])


# Function to check if a policy is already attached
def is_policy_attached(policy_name, target_ou_id):
    paginator = client.get_paginator('list_policies_for_target')
    for page in paginator.paginate(TargetId=target_ou_id, Filter='SERVICE_CONTROL_POLICY'):
        for policy in page['Policies']:
            if policy['Name'] == policy_name:
                return True
    return False

# Function to create and attach policies
def create_and_attach_policy(policy_filename, target_ou_id):
    policy_name = policy_filename.split('.')[0]

    # Check if the policy is already attached
    if is_policy_attached(policy_name, target_ou_id):
        print(f"Policy {policy_name} is already attached to OU {target_ou_id}.")
        return


    # Read the SCP policy from the JSON file
    policy_file_path = os.path.join(policies_folder_path, policy_filename.strip())

    # Check if the file exists
    if not os.path.exists(policy_file_path):
        print(f"File not found: {policy_file_path}")
        return
    
    with open(policy_file_path, 'r') as policy_file:
        policy_content = json.load(policy_file)

    # Create the SCP policy
    response = client.create_policy(
        Content=json.dumps(policy_content),
        Description=f'Policy from {policy_filename}',
        Name=policy_filename.split('.')[0],
        Type='SERVICE_CONTROL_POLICY'
    )
    # Extract the Policy ID from the response
    policy_id = response['Policy']['PolicySummary']['Id']
   
    # Attach the SCP policy to the target OU
    client.attach_policy(
        PolicyId=policy_id,
        TargetId=target_ou_id
    )
    print(f"Policy {policy_id} has been created and attached to OU {target_ou_id}.")

# Iterate over each OU and its associated policies
for ou_id, policies in policy_dict.items():
    for policy_file in policies:
        if policy_file:  # Ensure the policy file is not an empty string
            create_and_attach_policy(policy_file.strip(), ou_id)