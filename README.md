# AWS Sensitive Permissions

This script enumerates the permissions of all the AWS principals (groups, users & roles) using all the given profiles and prints the ones that have interesting permissions:
- **Adminitrator (*) privileges**
- **Privilege Escalation privileges** (based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation)
- **Privileges to perform potential sensitive actions / Indirect privilege escalations** (based on https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation)

Moreover, this tool offer **3 ways to find sensitive permissions**:
- Using a **YAML file with sensitive and privescs permissions predefined** (as indicated previously).
- Using **OpenAI to ask** if a set of permissions contains sensitive or a privesc permissions.
- Checking for **permissions not included in the ReadOnly** managed policy.

If you only want the output of 1 or 2 of the methods, you can use the `--only-yaml`, `--only-openai` or `--only-no-readonly` flags together.

If you know more interesting AWS permissions feel free to send a **PR here and to [HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)**

## Quick Start

```bash
pip3 install -r requirements.txt

# Help
python3 aws_sensitive_permissions.py  -h
Find AWS sensitive permissions given to principals in the specified profiles. This tool offer 3 ways to find sensitive permissions.
If you only want the output of 1 or 2 of the methods, you can use the --only-yaml, --only-openai or --only-no-readonly flags together.
usage: aws_sensitive_permissions.py [-h] [-k API_KEY] [-v] [--only-yaml] [--only-openai] [--only-no-readonly]
                                    profiles [profiles ...]

Find AWS sensitive permissions given to principals in the specified profiles. This tool offer 3 ways to find sensitive
permissions. If you only want the output of 1 or 2 of the methods, you can use the --only-yaml, --only-openai or --only-
no-readonly flags together.

positional arguments:
  profiles              One or more AWS profiles to check.

options:
  -h, --help            show this help message and exit
  -k API_KEY, --api-key API_KEY
                        OpenAI API key. The env variable OPENAI_API_KEY can also be used.
  -v, --verbose         Get info about why a permission is sensitive or useful for privilege escalation.
  --only-yaml           Only check permissions inside the yaml file
  --only-openai         Only check permissions with OpenAI
  --only-no-readonly    Only check permissions with OpenAI

# Run the 3 modes with 3 profiles
python3 aws_sensitive_permissions.py profile-name profile-name2 profile-name3 -k <openai_api_key> -v

# Run only the yaml mode with 1 profile
python3 aws_sensitive_permissions.py profile-name --only-yaml -v

# Run only the openai mode with 1 profile
python3 aws_sensitive_permissions.py profile-name --only-openai -k <openai_api_key> -v

# Run only the no-readonly mode with 1 profile
python3 aws_sensitive_permissions.py profile-name --only-no-readonly -v
```
