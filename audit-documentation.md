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
