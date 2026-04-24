---
name: aws-secrets-rotation
description: "Automate AWS secrets rotation for RDS, API keys, and credentials"
category: cybersecurity
risk: safe
source: community
tags: "[aws, secrets-manager, security, automation, credentials]"
date_added: "2026-02-27"
---

# AWS Secrets Rotation

Automate rotation of secrets, credentials, and API keys using AWS Secrets Manager and Lambda.

## When to Use
Use this skill when you need to implement automated secrets rotation, manage credentials securely, or comply with security policies requiring regular key rotation.

## Supported Secret Types
- RDS database credentials
- DocumentDB, Redshift, ElastiCache credentials
- API keys, OAuth tokens, SSH keys
- Custom credentials

## Full Documentation
See the original SKILL.md in the Aegis Nexus codebase for complete Secrets Manager setup, Lambda rotation functions, CloudWatch monitoring, compliance tracking scripts, and best practices.
