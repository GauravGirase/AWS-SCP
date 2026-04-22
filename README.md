# AWS-SCP
AWS Service Control Policy (SCP)—a type of policy used in Amazon Web Services Organizations to set permission guardrails across accounts. It doesn’t grant permissions; it restricts what cannot be done, even if an IAM policy would otherwise allow it.

## Policy 1
```bash
{
  "Version": "2012-10-17", # policy language version, "2012-10-17" standard version used for IAM and SCP policies.
  "Statement": [  # Each object inside defines a specific permission or restriction.
    {
      "Effect": "Deny", # explicitly block the action
      "Action": [
        "iam:CreateLoginProfile" # "iam:CreateLoginProfile" refers to creating a console login (username + password) for an IAM user.
      ],
      "Resource": "arn:aws:iam::*:user/*"
    }
  ]
}
```
**Explaination:** Deny the ability to create login profiles (console passwords) for any IAM user in any account.
**Note:** explicit Deny always overrides Allow
**"Resource": "arn:aws:iam::*:user/*"**
- arn:aws:iam:: → IAM service ARN
- '*' → applies to all AWS accounts in the organization
- user/* → applies to all IAM users
## Common reasons:
- Enforce no IAM user passwords (security best practice)
- Require centralized authentication (e.g., SSO)
- Reduce risk of credential compromise

## Policy 2 - lock down the root user unless MFA is enabled
```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUnlessMFA",
      "Effect": "Deny",
      "NotAction": [ # Deny everything EXCEPT the listed actions
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetAccountSummary",
        "iam:ListAccountAliases",
        "iam:ListVirtualMFADevices",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:DeleteVirtualMFADevice",
        "iam:DeactivateMFADevice",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalType": "Account" # applies to the root user of the account (not IAM users or roles)
        },
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false" # MFA is not present / not used in the session
        }
      }
    }
  ]
}
```
**BoolIfExists** means:
- If the key exists → evaluate it
- If it doesn’t exist → don’t fail the condition
## Policy 3 - Prevent any AWS account in the organization from leaving the organization.
```bash
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "organizations:LeaveOrganization", # It allows a member account to remove itself from an AWS Organization.
        "Resource": "*"
      }
    ]
  }
```
### Why this matters
- Member accounts can (by default, depending on settings) leave the organization.
- If they leave:
  - SCPs no longer apply
  - Central governance is lost
  - Billing and security controls are bypassed
- Organizations attach this SCP at: The root OU (top level)

## Policy 4 - prevents deletion of logs (or any data) in a specific S3 bucket.
```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDeleteActionsOnLogArchives",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteBucket", # Prevents deleting the entire bucket
        "s3:DeleteObject", # Prevents deleting current objects
        "s3:DeleteObjectVersion" # Prevents deleting specific versions (important if versioning is enabled)
      ],
      "Resource": [
        "arn:aws:s3:::<BUCKET_NAME>",
        "arn:aws:s3:::<BUCKET_NAME>/*"
      ]
    }
  ]
}
```
Typically used to protect log archives (CloudTrail, access logs, etc.).

## Policy 5 - protecting a specific CloudTrail trail from being tampered with—it ensures logging stays on and cannot be weakened or removed.
```bash
{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AWSCloudTrailManagement",
        "Effect": "Deny",
        "Action": [
          "cloudtrail:StopLogging", # Prevents turning off logging
          "cloudtrail:DeleteTrail", # Prevents deleting the trail entirely
          "cloudtrail:PutEventSelectors", # Prevents changing what events are logged
          "cloudtrail:UpdateTrail" # Prevents modifying trail settings
        ],
        "Resource": "arn:aws:cloudtrail:<REGION>:<ACCOUNT_ID>:trail/<trail-name>"
      }
      
    ]
    
  }
```
**So this SCP applies only to that named trail—not all trails.**
If an attacker gains access, one of the first things they might try is:
- Disable logging
- Delete trails
- Reduce visibility

## Policy 6 - CloudTrail trail must remain exactly as it is—no deletion, no modification, no stopping.
```bash
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EnableLogFileIntegrityValidation",
            "Effect": "Deny",
            "Action": [
                "cloudtrail:DeleteTrail",
                "cloudtrail:PutEventSelectors",
                "cloudtrail:StopLogging",
                "cloudtrail:UpdateTrail"
            ],
            "Resource": "arn:aws:cloudtrail:region:acct-id:trail/trail-name"
          }
    ]
}
```
## Policy 7 - protecting AWS Config so it can’t be turned off or dismantled
```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableAWSConfig",
      "Effect": "Deny",
      "Action": [
        "config:DeleteConfigurationRecorder", # 
        "config:DeleteDeliveryChannel", # Prevents deleting where Config sends data (e.g., S3 bucket, SNS)
        "config:DeleteRetentionConfiguration", # Prevents removing retention rules (how long data is kept)
        "config:StopConfigurationRecorder", # revents turning off AWS Config recording
        "config:DeleteAggregationAuthorization", # Prevents removing permissions for cross-account aggregation
        "config:DeleteConfigurationAggregator" # Prevents deleting aggregated views across accounts
      ],
      "Resource": "*"
    }
  ]
}
```
This SCP enforces:
- You cannot stop AWS Config
- You cannot delete its components
- You cannot dismantle org-wide aggregation

AWS Config is used for:
- Tracking resource changes
- Compliance monitoring
- Auditing configurations
## Policy 8 - Deny creating long-term access keys for the root user.
```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreateAccessKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalARN": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```
# Automation 
## Step 1: Congiuration
```bash
# config.ini
[SCOPES]
policy_dict = { 
    "<ROOT_OU_ID>": ["denyLeaveOrganization.json"], ["denyConfigChange.json"], ["denyRootAccessKey.json"], 
    "<COMPLIANT_OU_ID>": ["denyLoginIAM.json"], ["denyRootUnlessMFA.json"], ["denyDeleteActionsOnLogArchives.json"], ["denyAWSCloudTrailManagement.json"], ["denyLogFileIntegrityValidation.json"]}

[PATHS]
policies_folder_path = ../policies
```
Update ROOT_OU_ID & COMPLIANT_OU_ID

## Step 2 - ENV setup
### Install the dependencies
```bash
pip install boto3
pip install pytest pytest-json-report
```
### Set all AWS credential that has permission on Organization SCP, also another credential as a user to validate the test
```bash
export AWS_PROFILE=admin (with permission to Organization SCP)
export AWS_PROFILE=user (for testing)
```
## Step 3 - Commands to use
- To create and attach the policy to OU, (note that for this, you have to set aws credential to admin)
```bash
python3 policy_apply.py 
```
- To detach and delete policy from OU, (note that for this, you have to set aws credential to admin)
```bash
python3 policy_remove.py
```