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
- * → applies to all AWS accounts in the organization
- user/* → applies to all IAM users
## Common reasons:
- Enforce no IAM user passwords (security best practice)
- Require centralized authentication (e.g., SSO)
- Reduce risk of credential compromise