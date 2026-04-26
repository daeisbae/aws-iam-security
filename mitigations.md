## 3. Mitigations

### 3.1 AWS CloudTrail

CloudTrail is AWS audit logging service that records all API calls and administrative actions in your AWS account. You can use this record to search for any security detection and investigations.

![cloudtrail creation](images/aws_cloudtrail_create_trail.png)
Create a trail workflow in order to record the logs. After creating the trail, you can log and view all the logs happen after that.

![cloudtrail assume role detection](images/aws_cloudtrail_switchrole_event_1.png)
You can detect [sts::AssumeRole](users-roles-groups.md#13-roles) by searching for switchrole in cloudtrail. If you click the event, you can get further information in detail.

![cloudtrail detection specifics](images/aws_cloudtrail_switchrole_event_2.png)
![cloudtrail detection specifics](images/aws_cloudtrail_switchrole_event_3.png)
Here you can get the event information such as ip address of the source, instance/resource it used, the user/role it used for the access, the web browser information (user-agent) used to connect to the instance.

### 3.2 AWS Config

AWS Config is a compliance monitoring service that continuously tracks your AWS resource configurations and evaluates them against security best practices. Config warns you about dangerous configurations before they can be exploited.

![config iam setting](images/aws_config_setting_iam.png)
First, we need to enable AWS Config to monitor IAM resources. Start the configuration process to track IAM policies, roles, and users.

![config iam rules](images/aws_config_iam_rule.png)
AWS Config provides managed rules specifically for IAM security (There's others, but I specifically filtered the rules for IAM).

![config setting review](images/aws_config_setting_review.png)
Review the configuration settings before enabling Config. This will start monitoring all changes to your IAM resources and evaluate them against compliance rules automatically.

![config compliance status](images/aws_config_iam_rules_compliance_status.png)
The compliance dashboard shows which IAM resources violate security best practices. Here it shows I got few IAM bad practices such as password weakness, inline policy for AssumeRole.

### 3.3 AWS GuardDuty

AWS GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior to protect your AWS accounts, workloads, and data. GuardDuty finds threats by analyzing AWS CloudTrail event logs, VPC Flow Logs, and DNS logs.

![guardduty configuration for ec2](images/aws_guardduty_ec2_monitoring_setup_1.png)
First, enable GuardDuty. Then goto "Runtime Monitoring" to configure the service to monitor EC2 instances.

![vpc flow log configuration for guardduty](images/aws_guardduty_ec2_monitoring_setup_2.png)
Next, you need to enable VPC Flow Logs to monitor network traffic. This is required for GuardDuty to analyze network activity and detect threats.

![guardduty ec2 monitoring dashboard](images/aws_guardduty_dashboard.png)
The GuardDuty dashboard shows the status of your threat detection setup. It will start monitoring your instances and network traffic for suspicious activity.

#### 3.3.1 Running Nmap for Ping Sweep

Let's say your instance is compromised and the attacker is trying to scan your network using Nmap. GuardDuty will detect this malicious activity.

```bash
nmap -sn <target-ip>/<cidr>
```

![guardduty nmap detection](images/aws_guardduty_ec2_nmap_detection_1.png)
GuardDuty will alert you about the Nmap scan attempt. You can see the details of the detection.

![guardduty nmap detection details 1](images/aws_guardduty_ec2_nmap_detection_2.png)
![guardduty nmap detection details 2](images/aws_guardduty_ec2_nmap_detection_3.png)
![guardduty nmap detection details 3](images/aws_guardduty_ec2_nmap_detection_4.png)
You can see the specific details of the Nmap scan, including the instance, hacker details, and the process used for the attack. This helps you understand the attacker's intent and take appropriate action.

#### 3.3.2 Unusual API Calls from unusual IP

If an attacker is using the compromised instance to make unusual API calls, GuardDuty will also detect this. For example, you can extract the EC2 instance credentials from the metadata using the command `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. This can extract the temporary role credentials used by the instance.

Using these credentials, the attacker can use the AWS CLI to make API calls. For example, they can start enumerating IAM users:

```bash
aws iam list-users --profile <role-name>
```

![kali linux aws enum using ec2 role credentials](images/aws_guardduty_ec2_kali_enum.png)
Using the credentials extracted from the metadata, the attacker can use the AWS API key to enumerate IAM users and perform other actions. GuardDuty will detect this unusual activity.

> [!IMPORTANT]
> You need to extract the credentials from the metadata endpoint and use them in different endpoint to make API calls to trigger GuardDuty detection.

![guardduty unusual api call detection](images/aws_guardduty_ec2_kali_detection_1.png)
![guardduty list-users detection 1](images/aws_guardduty_ec2_kali_detection_2.png)
![guardduty list-users detection 2](images/aws_guardduty_ec2_kali_detection_3.png)
GuardDuty will alert you about the unusual API calls made from the compromised instance. You can see the details of the detection, including the specific API calls made and the instance involved.

### 3.4 AWS IAM Access Analyzer

AWS IAM Access Analyzer helps you identify resources in your account that are shared with other AWS accounts or is unused.

![create unused access analyzer](images/aws_iam_access_analyzer_create_unused_access.png)
First, you need to create an Access Analyzer. "Unused access analyzer" will identify resources that are not being used.

![unused access analyzer dashboard](images/aws_iam_access_analyzer_unused_access_dashboard.png)
Next, you can see the dashboard of the unused access analyzer.

![unused account](images/aws_iam_access_analyzer_unused_account.png)
The unused password shows the accounts that have not been used for the set period of time which we configured it for 3 days.

![unused access by admin](images/aws_iam_access_analyzer_unused_access_admin_1.png)
We can see all the unused permission by admin account. This is useful to identify unused permissions that can be removed to reduce the attack surface

![permission recommendation for admin](images/aws_iam_access_analyzer_unused_access_admin_2.png)
![permission recommendation for admin](images/aws_iam_access_analyzer_unused_access_admin_3.png)
You can see the permission recommendation for the admin account to remove unused permissions.

### 3.5 AWS Organizations and SCP Guardrails

AWS Organizations lets you group AWS accounts and apply service control policies to those accounts. An SCP sets the maximum permission that can be used in an account. It does not grant permission by itself. The user or role still needs IAM permission inside the account.

In this lab, we will use SCPs to protect the aws-iam-security-lab member account from the IAM privilege escalation paths shown earlier.

First, we opened AWS Organizations and created an organization with all features enabled.

![aws organizations create home](images/aws_organizations_create_home.png)
The AWS Organizations start page gives the option to create an organization for multiple AWS accounts.

![aws organizations create consideration](images/aws_organizations_create_consideration.png)
![aws organizations created success](images/aws_organizations_created_success.png)
Now we can see the organization was created successfully.

Next, we created an OU called "Sandbox". This OU is used for the lab account so the SCPs do not affect the management account.

![aws organizations create ou menu](images/aws_organizations_create_ou_menu.png)
Here, we selected the root and used the Actions menu to create a new organizational unit.

![aws organizations create ou sandbox](images/aws_organizations_create_ou_sandbox.png)
We named the organizational unit "Sandbox".

Then we created a member account called "aws-iam-security-lab".

![aws organizations create account form](images/aws_organizations_create_account_form.png)

After the member account was created, we moved it into the "Sandbox" OU.

![aws organizations move account menu](images/aws_organizations_move_account_menu.png)
Here, we selected "aws-iam-security-lab" and chose Move.

![aws organizations move account destination](images/aws_organizations_move_account_destination.png)
The destination is the "Sandbox" OU.

![aws organizations sandbox account](images/aws_organizations_sandbox_account.png)
Now we can see "aws-iam-security-lab" inside the "Sandbox" OU. Any SCP attached to "Sandbox" applies to this lab member account.

Next, we enabled service control policies.

![aws organizations policy types](images/aws_organizations_policy_types.png)
Under AWS Organizations policies, we selected Service control policies.

![aws scp enable service control policies](images/aws_scp_enable_service_control_policies.png)
SCPs must be enabled before we can attach custom guardrails to the OU.

The first custom SCP is called "DenySensitiveIAMChanges". This policy blocks IAM actions that can be used for self-escalation in this repo.

![aws scp create deny sensitive iam changes](images/aws_scp_create_deny_sensitive_iam_changes.png)
Here, we created the "DenySensitiveIAMChanges" policy.

```json
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Sid": "DenyDangerousIamEscalationActionsExceptTrustedAdmins",
   "Effect": "Deny",
   "Action": [
    "iam:CreateAccessKey",
    "iam:PutUserPolicy",
    "iam:AttachUserPolicy",
    "iam:PutGroupPolicy",
    "iam:AttachGroupPolicy",
    "iam:AddUserToGroup",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion"
   ],
   "Resource": "*",
   "Condition": {
    "ArnNotLike": {
     "aws:PrincipalArn": [
      "arn:aws:iam::*:role/SecurityAdmin",
      "arn:aws:iam::*:role/OrganizationAccountAccessRole"
     ]
    }
   }
  }
 ]
}
```

This SCP blocks the risky IAM actions for normal users and roles. We added trusted admin role exceptions so the lab can still be cleaned up from the approved admin path.

The second custom SCP is called DenyPassingAdminRoles. This policy blocks `iam:PassRole` when the role name looks like an admin role.

![aws scp create deny passing admin roles](images/aws_scp_create_deny_passing_admin_roles.png)
Here, we created the DenyPassingAdminRoles policy.

```json
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Sid": "DenyPassingAdminRolesToServicesExceptTrustedAdmins",
   "Effect": "Deny",
   "Action": "iam:PassRole",
   "Resource": [
    "arn:aws:iam::*:role/AdminAccess",
    "arn:aws:iam::*:role/*Admin*",
    "arn:aws:iam::*:role/*Administrator*"
   ],
   "Condition": {
    "ArnNotLike": {
     "aws:PrincipalArn": [
      "arn:aws:iam::*:role/SecurityAdmin",
      "arn:aws:iam::*:role/OrganizationAccountAccessRole"
     ]
    }
   }
  }
 ]
}
```

This SCP is meant to stop the EC2 privilege escalation path where a user launches an instance with an admin instance profile.

After creating both policies, we can see them in the SCP policy list.

![aws scp available policies](images/aws_scp_available_policies.png)
The custom policies are listed with the AWS managed `FullAWSAccess` policy.

Before attaching the custom SCPs, the Sandbox OU had `FullAWSAccess` available through the root path.

![aws scp sandbox policies before](images/aws_scp_sandbox_policies_before.png)
![aws scp sandbox policies inherited](images/aws_scp_sandbox_policies_inherited.png)
Here, we can see the inherited `FullAWSAccess` policy from the root.

Finally, attach these policies to the `Sandbox` OU

- `FullAWSAccess`
- `DenySensitiveIAMChanges`
- `DenyPassingAdminRoles`

![aws scp attach policy selection](images/aws_scp_attach_policy_selection.png)

![aws scp sandbox policies after](images/aws_scp_sandbox_policies_after.png)

`FullAWSAccess` stays attached because this lab uses a deny list SCP setup. It allows the account to use AWS services at the SCP layer, while the two custom SCPs block the dangerous IAM paths. The final permission still depends on the IAM policy inside the member account.

After attaching the SCPs, we retest the four exploit scenarios from [section 2](exploits.md#2-exploits). The expected result is that IAM may allow the test user to try the action, but the SCP blocks the final request in the `aws-iam-security-lab` account.

#### 3.5.1 Retest 1 - sts::AssumeRole Self-Escalation Path

For the first retest, we started with the `sts:AssumeRole` self-escalation path from [section 2.1](exploits.md#21-iam-privilege-escalation---stsassumerole). The goal was to prepare an iam-service user that could normally create its own inline policy, then confirm the `DenySensitiveIAMChanges` SCP blocks the escalation path inside the Sandbox OU.

![aws retest assumerole create iam service user](images/aws_retest_assumerole_create_iam_service_user.png)
First, we created an admin role in the member account. This retest uses `AdminAccessRole`, which has the same purpose as the earlier `AdminAccess` role from the exploit walkthrough.

![aws retest assumerole admin role permission](images/aws_retest_assumerole_admin_role_permission.png)
Here, we selected the AWS managed `AdministratorAccess` policy for the role.

![aws retest assumerole admin role review](images/aws_retest_assumerole_admin_role_review.png)
The trust policy allows same-account role assumption in the lab account. This gives us a privileged role to test against during the retest.

Then we created a customer managed policy named iam-service-policy. The policy allows iam-service to call iam:PutUserPolicy on itself.

```json
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": "iam:PutUserPolicy",
   "Resource": "arn:aws:iam::<member-account-id>:user/iam-service"
  }
 ]
}
```

![aws retest assumerole put user policy allow](images/aws_retest_assumerole_putuserpolicy_allow.png)
This permission is dangerous because the user can add an policy that allows `sts:AssumeRole` into an admin role.

![aws retest assumerole policy review](images/aws_retest_assumerole_policy_review.png)
The policy review page shows that the policy grants limited IAM permission management for iam-service.

We then tried to attach iam-service-policy directly to the iam-service user.

![aws retest assumerole attach policy to user](images/aws_retest_assumerole_attach_policy_to_user.png)
The selected policy would normally give the user enough permission to continue the self escalation test.

![aws retest assumerole user review](images/aws_retest_assumerole_user_review.png)
The final user review shows iam-service-policy attached as a permissions policy before creation.

When we created the user, AWS created iam-service, but it failed to attach the policy. This pass used the member account root user, and the SCP still applied because root is inside the member account and is not one of the exception roles in the policy. The error shows an explicit deny from a service control policy.

![aws retest assumerole scp attach user policy denied](images/aws_retest_assumerole_scp_attachuserpolicy_denied.png)
This is the expected guardrail behavior for the first retest. The `DenySensitiveIAMChanges` SCP blocks `iam:AttachUserPolicy`, so the user cannot receive the policy that would allow it to create its own `sts:AssumeRole` path.

![aws retest assumerole cloudtrail attach user policy denied](images/aws_retest_assumerole_cloudtrail_attachuserpolicy_denied.png)
CloudTrail also recorded the denied request.

This retest shows that the SCP blocks the policy attachment step in the member account. A later pass can run the exact `iam:PutUserPolicy` or `sts:AssumeRole` denial as iam-service if we want evidence for the final exploit action as well.

