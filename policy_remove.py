import boto3
import os
import configparser
import json

# Initialize a session using Amazon Organizations
client = boto3.client('organizations')

# Read configuration from config.ini
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

# Read and parse the policy dictionary from the config file
policy_dict = json.loads(config['SCOPES']['policy_dict'])


# Function to detach and delete policies
def detach_and_delete_policy(policy_id, target_ou_id):

    # Detach the SCP policy from the target OU
    client.detach_policy(
        PolicyId=policy_id,
        TargetId=target_ou_id
    )
    print(f"Policy {policy_id} has been detached from OU {target_ou_id}.")
    
    # Delete the SCP policy
    client.delete_policy(
        PolicyId=policy_id
    )
    print(f"Policy {policy_id} has been deleted.")

# Function to list and detach policies for a given OU
def list_and_detach_policies(target_ou_id, policy_names):
    paginator = client.get_paginator('list_policies_for_target')
    for page in paginator.paginate(TargetId=target_ou_id, Filter='SERVICE_CONTROL_POLICY'):
        for policy in page['Policies']:
            policy_name = policy['Name']
            policy_id = policy['Id']
            if policy_name in policy_names:
                detach_and_delete_policy(policy_id, target_ou_id)

# Iterate over each OU and its associated policies
for ou_id, policies in policy_dict.items():
    policy_names = [policy.split('.')[0] for policy in policies if policy]
    list_and_detach_policies(ou_id, policy_names)

print("All specified policies have been detached and deleted.")