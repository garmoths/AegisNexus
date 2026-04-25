---
name: aws-security-audit
description: "Comprehensive AWS security posture assessment using AWS CLI and security best practices"
category: cybersecurity
risk: safe
source: community
tags: "[aws, security, audit, compliance, security-assessment]"
date_added: "2026-02-27"
---

# AWS Security Audit

Perform comprehensive security assessments of AWS environments to identify vulnerabilities and misconfigurations.

## When to Use
Use this skill when you need to audit AWS security posture, identify vulnerabilities, or prepare for compliance assessments.

## Audit Categories

**Identity & Access Management**
- Overly permissive IAM policies
- Unused IAM users and roles
- MFA enforcement gaps
- Root account usage
- Access key rotation

**Network Security**
- Open security groups (0.0.0.0/0)
- Public S3 buckets
- Unencrypted data in transit
- VPC flow logs disabled
- Network ACL misconfigurations

**Data Protection**
- Unencrypted EBS volumes
- Unencrypted RDS instances
- S3 bucket encryption disabled
- Backup policies missing
- KMS key rotation disabled

**Logging & Monitoring**
- CloudTrail disabled
- CloudWatch alarms missing
- VPC Flow Logs disabled
- S3 access logging disabled
- Config recording disabled

## Full Documentation
See the original SKILL.md in the Aegis Nexus codebase for complete AWS CLI commands, security audit scripts, compliance mapping, and remediation priorities.
