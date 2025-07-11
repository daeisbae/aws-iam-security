# aws-iam-security

## Users vs Roles vs User Groups

We will first investigate the difference between Users, Roles, and User Groups

### User Groups

User Groups are like a folder for IAM users. You can add users to that folder then attach permission policies to it. Any user in the group automatically gets those permissions. This way you can manage access for many users at once.

![iam user group dashboard](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_group_dashboard.png)
First, we will see the IAM - User Group Dashboard. Currently we did not create any group yet.

![iam user group create page](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_group_create_iam_management.png)
We will create an "IAM Management" user group, where IT service department (imaginary) can help you with the account creation and troubleshooting.

![iam user group IAM permissions](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_group_iam_permissions.png)
Here, I assigned all the permissions except the Root password create, delete, and audit permission. Since the IT department should not have the control of root but left the "IAM Full Access" permission which can be misused. (Will be exploited later in the lab)

### Users

Users are account for a person or an application.  You give it a name and credentials (a password or access keys) so it can sign in or call AWS services.  You can attach permission policies to that user to grant it the rights it needs.

![iam user create](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_create_user_detail.png)
We will create an account called iam-service, so helpdesk professionals can use this account to resolve account troubleshooting.

![iam user assign permission](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_create_assign_permission.png)
We will assign the "IAM-Management" permission which we created earlier. We will demonstrate the privilege escalation later using this account

![iam user creation review](https://github.com/daeisbae/aws-iam-security/blob/main/images/aws_iam_user_create_user_review.png)
Now we can review the new user detail and create it.

### Roles

## Mitigations

### AWS IAM Access Analyzer

### AWS Config
