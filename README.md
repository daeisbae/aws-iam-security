# AWS IAM Security

This repository is an AWS IAM security case study. It shows how common IAM permissions can create privilege escalation paths, then documents the detections, evidence requirements, and remediation controls needed to review the same issues in an audit.

## Table of Contents

- [AWS IAM Security](#aws-iam-security)
  - [Table of Contents](#table-of-contents)
  - [1. Users vs Roles vs User Groups](users-roles-groups.md#1-users-vs-roles-vs-user-groups)
    - [1.1 User Groups](users-roles-groups.md#11-user-groups)
    - [1.2 Users](users-roles-groups.md#12-users)
    - [1.3 Roles](users-roles-groups.md#13-roles)
  - [2. Exploits](exploits.md#2-exploits)
    - [2.1 IAM Privilege Escalation - sts::AssumeRole](exploits.md#21-iam-privilege-escalation---stsassumerole)
    - [2.2 EC2 Privilege Escalation - ec2::RunInstances and iam::PassRole](exploits.md#22-ec2-privilege-escalation---ec2runinstances-and-iampassrole)
    - [2.3 IAM Privilege Escalation - iam::CreateAccessKey](exploits.md#23-iam-privilege-escalation---iamcreateaccesskey)
    - [2.4 IAM Privilege Escalation - iam::AddUserToGroup](exploits.md#24-iam-privilege-escalation---iamaddusertogroup)
  - [3. Mitigations](mitigations.md#3-mitigations)
    - [3.1 AWS CloudTrail](mitigations.md#31-aws-cloudtrail)
    - [3.2 AWS Config](mitigations.md#32-aws-config)
    - [3.3 AWS GuardDuty](mitigations.md#33-aws-guardduty)
      - [3.3.1 Running Nmap for Ping Sweep](mitigations.md#331-running-nmap-for-ping-sweep)
      - [3.3.2 Unusual API Calls from unusual IP](mitigations.md#332-unusual-api-calls-from-unusual-ip)
    - [3.4 AWS IAM Access Analyzer](mitigations.md#34-aws-iam-access-analyzer)
    - [3.5 AWS Organizations and SCP Guardrails](mitigations.md#35-aws-organizations-and-scp-guardrails)
      - [3.5.1 Retest 1 - sts::AssumeRole Self-Escalation Path](mitigations.md#351-retest-1---stsassumerole-self-escalation-path)
  - [4. Audit Documentation](audit-documentation.md#4-audit-documentation)
    - [4.1 Documentation Index](audit-documentation.md#41-documentation-index)
    - [4.2 Evidence Templates](audit-documentation.md#42-evidence-templates)
