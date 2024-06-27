# AWS Sensitive Permissions

This script enumerates the permissions of all the AWS principals (groups, users & roles) using all the given profiles and prints the ones that have privesc or sensitive permissions that haven't used them in a while.

A privilege escalation permission is a permission taht would allow a principal in AWS to obtain more permissions (by aumenting his own permissions or by pivoting to other principals for example).

A sensitive permission is a permission that could allow an attacker to perform actions that could be harmful for the organization (like deleting resources, reading sensitive data, etc).

- **Privilege Escalation privileges** are based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation
- **Privileges to perform potential sensitive actions / Indirect privilege escalations** are based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation

Moreover, this tool offer **3 ways to find sensitive permissions**:
- Using a **YAML file with sensitive and privescs permissions predefined** (as indicated previously).
- Using **OpenAI to ask** if a set of permissions contains sensitive or a privesc permissions.
- Checking for **permissions not included in the ReadOnly** managed policy.

If you only want the output of 1 or 2 of the methods, you can use the `--only-yaml`, `--only-openai` or `--only-no-readonly` flags together.

Note that by default the tool will filter out permissions assigned to specific resources (so not to `*`). You can re-enable this by using the `--all-resources` flag.


If you know more interesting AWS permissions feel free to send a **PR here and to [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)**

## Quick Start

```bash
pip3 install -r requirements.txt

# Help
usage: aws_iam_review.py [-h] [-k API_KEY] [-v] [--only-yaml] [--only-openai] [--only-no-readonly] [--all-resources] [--print-reasons] [--all-actions] [--merge-perms] profiles [profiles ...]

Find AWS unused sensitive permissions given to principals in the accounts of the specified profiles.

positional arguments:
  profiles              One or more AWS profiles to check.

options:
  -h, --help            show this help message and exit
  -k API_KEY, --api-key API_KEY
                        OpenAI API key. The env variable OPENAI_API_KEY can also be used.
  -v, --verbose         Get info about why a permission is sensitive or useful for privilege escalation.
  --only-yaml           Only check permissions inside the yaml file
  --only-openai         Only check permissions with OpenAI
  --all-resources       Do not filter only permissions over '*'
  --print-reasons       Print the reasons why a permission is considered sensitive or useful for privilege escalation.
  --all-actions         Do not filter permissions inside the readOnly policy
  --merge-perms         Print permissions from yaml and OpenAI merged

# Run the 3 modes with 3 profiles
python3 aws_sensitive_permissions.py profile-name profile-name2 profile-name3 -k <openai_api_key> -v

# Run only the yaml mode with 1 profile
python3 aws_sensitive_permissions.py profile-name --only-yaml -v

# Run only the openai mode with 1 profile
python3 aws_sensitive_permissions.py profile-name --only-openai -k <openai_api_key> -v

# Run only the no-readonly mode with 1 profile
python3 aws_sensitive_permissions.py profile-name --only-no-readonly -v
```
