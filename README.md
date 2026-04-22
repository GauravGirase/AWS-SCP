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