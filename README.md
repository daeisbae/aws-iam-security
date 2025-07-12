# AWS IAM Security

This repository demonstrates common AWS IAM security vulnerabilities and privilege escalation techniques through hands-on examples. You will learn how seemingly harmless IAM configurations can lead to complete account compromise, and more importantly, how to prevent these security gaps

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

## 2. Exploit

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

## 3. Mitigations

### 3.1 AWS IAM Access Analyzer

### 3.2 AWS Config
