import os
import boto3
import yaml
import fnmatch
import argparse
import tiktoken
import openai
import json
from termcolor import colored




#########################
##### YAML SETTINGS #####
#########################

# Load YAML data
with open("sensitive_permissions.yaml", "r") as file:
    PERMISSIONS_DATA = yaml.safe_load(file)


#########################
#### OPENAI SETTINGS ####
#########################
PERSONALITY = """You are an AWS security expert. You review polcies searching for sensitive or privilege escalation permissions.
A privilege escalation permission or set of permissions, is a permissions that could allow the user to escalate to other AWS principal (user, group or role) in any way. For example, a user with permissions to create a new lambda with a role can escalate to that role. Or a user with permission to add users to other IAM groups can escalate to those groups.
Sensitive permissions, are permissions that would allow a user to access sensitive data or perform sensitive actions. For example, a user with permissions to read secret manager or to modify infrastructure could be considered sensitive permissions.
Your answer is always a valid JSON without any other thing (it should start with '{' and end with '}')."""

FINAL_CLARIFICATIONS = """Your response must be a valid JSON with the format specified before (it should start with '{' and end with '}')."""

PROMPT = """An AWS principal has the permissions: __PERMISSIONS__
Check for privilege escalation and sensitive permissions and respond with a valid JSON with the following format:
{
    "privesc": ["permission1", "permission2"],
    "privesc_reasons": "Reason why the permissions are considered privilege escalation",
    "sensitive": ["permission3", "permission4"],
    "sensitive_reasons": "Reason why the permissions are considered sensitive"
}

Do not return permissions that could potentially with a low probability allow the user to read sensitive information.
Give only the permissions that will allow the user to perform sensitive actions or that higly probable will allow the user to access sensitive information (like read bucket, secrts, code...).
Do not return as reason of sensitive permissions that there wasn't privilege escalation permissions.

It's possible that the given permissions are not privilege escalation or sensitive permissions. In that case, return an empty array for the permissions and an empty string for the reasons.
"""


def get_len_tokens(prompt, model="gpt-4"):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(prompt))

def remove_fences(text: str) -> str:
    """Function that removes code fences from the response"""

    text = text.strip()
    if len(text.split("```")) == 3:
        text = "\n".join(text.split("```")[1].split("\n")[1:])
    
    elif len(text.split("```")) > 3:
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
        if text.endswith("```"):
            text = "\n".join(text.split("\n")[:-1])
            
    return text


def fix_json(orig_text: str, orig_response: str, json_error: str) -> str:
    """Function that asks to fix a given json"""

    all_msg = f"{orig_text}\n\n You already gave this reponse:\n{orig_response}\n\nWhich resulted in this error:\n{json_error}\n\nPlease fix it and respond with a valid json."
    response = contact(all_msg)
    return response

# Ask OpenAI
def contact(prompt: str, p_info_msg: bool = True, model: str = "gpt-4") -> str:
    """Function that asks the model"""
    
    while get_len_tokens(prompt) > 7000:
        prompt = "\n".join(prompt.splitlines()[:-1])

    messages = [
        {"role": "system", "content": PERSONALITY},
        {"role": "user", "content": prompt},
        {"role": "system", "content": FINAL_CLARIFICATIONS}
    ]

    try:
        response = openai.ChatCompletion.create(
            model=model,
            messages=messages,
            temperature=0
        )
    except Exception as e:
        print(f"{colored('[-] Error contacting OpenAI: ', 'yellow')}" + str(e))
        return None

    all_text = response["choices"][0]["message"]["content"]

    all_text = remove_fences(all_text)
    try:
        json_text = json.loads(all_text)
    except json.decoder.JSONDecodeError as e:
        json_text = fix_json(prompt, all_text, str(e))

    return json_text


########################
## READ ONLY SETTINGS ##
########################

def get_readonly_perms(profile):
    global READONLY_PERMS
    
    # Get the policy ARN for the ReadOnly managed policy
    # Note: For AWS managed policies, the ARN pattern is arn:aws:iam::aws:policy/ReadOnlyAccess
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    session = boto3.Session(profile_name=profile)
    iam = session.client("iam")

    # Retrieve the policy details
    policy = iam.get_policy(PolicyArn=policy_arn)
    policy_version_id = policy['Policy']['DefaultVersionId']

    # Retrieve the policy document
    policy_version = iam.get_policy_version(
        PolicyArn=policy_arn, 
        VersionId=policy_version_id
    )

    perms = []
    for statement in policy_version['PolicyVersion']['Document']['Statement']:
        if statement['Effect'] != 'Allow':
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        perms.extend(actions)

    READONLY_PERMS = perms

# Function to combine all permissions from policy documents
def combine_permissions(policy_documents):
    permissions = []
    for document in policy_documents:
        for statement in document["Statement"]:
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            permissions.extend(actions)
    return permissions

# Function to check if a policy contains sensitive or privesc permissions
def check_policy(all_perm, arn, api_key, verbose, only_yaml, only_openai, only_no_readonly):
    global PERMISSIONS_DATA
    if not all_perm:
        return
    
    all_privesc_perms = []
    all_sensitive_perms = []
    all_privesc_perms_reasons = ""
    all_sensitive_perms_reasons = ""

    # Check yaml permissions
    if only_yaml or (not only_openai and not only_no_readonly):
        for aws_svc, permissions in PERMISSIONS_DATA.items():
            for perm_type in ["privesc", "sensitive"]:
                if perm_type in permissions:
                    
                    for perm in permissions[perm_type]:
                        if "," in perm:
                            required_perms = perm.replace(" ", "").split(",")
                        else:
                            required_perms = [perm]
                        
                        if "*" in all_perm:
                            msg = f"{colored('-', 'yellow')} {colored(arn, 'green')} has the " + colored("administrator", 'red') + " permission " + colored("*", 'red')
                            print(msg)
                            return

                        elif any(
                                all(fnmatch.fnmatch(p, p_pattern) for p in required_perms)
                            for p_pattern in all_perm):
                            
                            if perm_type == "privesc":
                                all_privesc_perms.extend(required_perms)
                                all_privesc_perms_reasons += ", ".join(permissions["urls"])
                            elif perm_type == "sensitive":
                                all_sensitive_perms.extend(required_perms)
                                all_sensitive_perms_reasons += ", ".join(permissions["urls"])
    


    all_sensitive_perms_ro = []

    # Check if permissions not in ReadOnly
    if only_no_readonly or (not only_yaml and not only_openai):
        if not READONLY_PERMS:
            print(f"{colored('[-] ', 'red')}No ReadOnly permissions found.")
        else:
            for perm in all_perm:
                if not any(fnmatch.fnmatch(perm, p_pattern) for p_pattern in READONLY_PERMS):
                    all_sensitive_perms_ro.append(perm)



    all_privesc_perms_ai = []
    all_sensitive_perms_ai = []
    all_privesc_perms_ai_reasons = ""
    all_sensitive_perms_ai_reasons = ""

    # Check permissions with OpenAI
    if only_openai or (not only_yaml and not only_no_readonly):
        if api_key:
            all_perm_str = ", ".join(all_perm)
            prompt = PROMPT.replace("__PERMISSIONS__", all_perm_str)
            response = contact(prompt)
            if response:
                if "privesc" in response:
                    all_privesc_perms_ai.extend(response["privesc"])
                    all_privesc_perms_ai_reasons = response["privesc_reasons"]
                if "sensitive" in response:
                    all_sensitive_perms_ai.extend(response["sensitive"])
                    all_sensitive_perms_ai_reasons = response["sensitive_reasons"]
    
    if all_privesc_perms:
        msg = f"{colored('-', 'yellow')} ({colored('HT', 'blue')}) {colored(arn, 'green')} has the {colored('privilege escalation', 'cyan')} permission(s): {colored(', '.join(all_privesc_perms), 'red')}"
        if verbose:
            msg += f" because {all_privesc_perms_reasons}"
        print(msg)
    
    if all_sensitive_perms:
        msg = f"{colored('-', 'yellow')} ({colored('HT', 'blue')}) {colored(arn, 'green')} has the {colored('sensitive', 'cyan')} permission(s): {colored(', '.join(all_sensitive_perms), 'red')}"
        if verbose:
            msg += f" because {all_sensitive_perms_reasons}"
        print(msg)
    
    if all_sensitive_perms_ro:
        msg = f"{colored('-', 'yellow')} ({colored('RO', 'blue')}) {colored(arn, 'green')} has the {colored('not in ReadOnly', 'cyan')} permission(s): {colored(', '.join(all_sensitive_perms_ro), 'red')}"
        print(msg)
    
    if all_privesc_perms_ai:
        msg = f"{colored('-', 'yellow')} ({colored('AI', 'blue')}) {colored(arn, 'green')} has the {colored('privilege escalation', 'cyan')} permission(s): {colored(', '.join(all_privesc_perms_ai), 'red')}"
        if verbose:
            msg += f" because {all_privesc_perms_ai_reasons}"
        print(msg)
    
    if all_sensitive_perms_ai:
        msg = f"{colored('-', 'yellow')} ({colored('AI', 'blue')}) {colored(arn, 'green')} has the {colored('sensitive', 'cyan')} permission(s): {colored(', '.join(all_sensitive_perms_ai), 'red')}"
        if verbose:
            msg += f" because {all_sensitive_perms_ai_reasons}"
        print(msg)


# Function to get inline and attached policies for a principal
def get_policies(principal_type, principal_name, arn, api_key, verbose, only_yaml, only_openai, only_no_readonly):
    policy_document = []

    if principal_type == "User":
        attached_policies = iam.list_attached_user_policies(UserName=principal_name)
    elif principal_type == "Role":
        attached_policies = iam.list_attached_role_policies(RoleName=principal_name)
    elif principal_type == "Group":
        attached_policies = iam.list_attached_group_policies(GroupName=principal_name)

    for policy in attached_policies["AttachedPolicies"]:
        policy_data = iam.get_policy(PolicyArn=policy["PolicyArn"])
        policy_version = iam.get_policy_version(
            PolicyArn=policy["PolicyArn"], VersionId=policy_data["Policy"]["DefaultVersionId"]
        )
        policy_document.append(policy_version["PolicyVersion"]["Document"])


    if principal_type == "User":
        inline_policies = iam.list_user_policies(UserName=principal_name)
    elif principal_type == "Role":
        inline_policies = iam.list_role_policies(RoleName=principal_name)
    elif principal_type == "Group":
        inline_policies = iam.list_group_policies(GroupName=principal_name)


    for policy_name in inline_policies.get("PolicyNames", []):
        if principal_type == "User":
            inlinepolicy = iam.get_user_policy(UserName=principal_name, PolicyName=policy_name)
        elif principal_type == "Role":
            inlinepolicy = iam.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
        elif principal_type == "Group":
            inlinepolicy = iam.get_group_policy(GroupName=principal_name, PolicyName=policy_name)
        
        policy_document.append(inlinepolicy["PolicyDocument"])

    if policy_document:
        all_perm = combine_permissions(policy_document)
        check_policy(all_perm, arn, api_key, verbose, only_yaml, only_openai, only_no_readonly)
    else:
        msg = f"- {arn} doesn't have any permissions"
        print(msg)
        

def main(profiles, api_key, verbose, only_yaml, only_openai, only_no_readonly):
    if not api_key:
        api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        print(f"{colored('[-] ', 'red')}No OpenAI API key specified.")
        if only_openai:
            print(f"{colored('[-] ', 'red')} Only OpenAI was specified without key. Exiting...")
    else:
        openai.api_key = api_key
    
    if only_no_readonly or (not only_yaml and not only_openai):
        get_readonly_perms(profiles[0])

    for profile in profiles:
        # Share the boto3 client with other functions
        session = boto3.Session(profile_name=profile)
        global iam
        iam = session.client("iam")

        # Get the account ID
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]

        print(f"Interesting permissions in {colored(account_id, 'yellow')} ({colored(profile, 'blue')}): ")

        # Check permissions for users
        for user in iam.list_users()["Users"]:
            get_policies("User", user["UserName"], user["Arn"], api_key, verbose, only_yaml, only_openai, only_no_readonly)

        # Check permissions for groups
        for group in iam.list_groups()["Groups"]:
            get_policies("Group", group["GroupName"], group["Arn"], api_key, verbose, only_yaml, only_openai, only_no_readonly)

        # Check permissions for roles
        for role in iam.list_roles()["Roles"]:
            get_policies("Role", role["RoleName"], role["Arn"], api_key, verbose, only_yaml, only_openai, only_no_readonly)
        
        print()


HELP = "Find AWS sensitive permissions given to principals in the specified profiles. This tool offer 3 ways to find sensitive permissions.\n"
HELP += "If you only want the output of 1 or 2 of the methods, you can use the --only-yaml, --only-openai or --only-no-readonly flags together."

if __name__ == "__main__":
    print(HELP)
    parser = argparse.ArgumentParser(description=HELP)
    parser.add_argument("profiles", nargs="+", help="One or more AWS profiles to check.")
    parser.add_argument("-k", "--api-key", help="OpenAI API key. The env variable OPENAI_API_KEY can also be used.")
    parser.add_argument("-v", "--verbose", default=False, help="Get info about why a permission is sensitive or useful for privilege escalation.", action="store_true")
    parser.add_argument("--only-yaml", default=False, help="Only check permissions inside the yaml file", action="store_true")
    parser.add_argument("--only-openai", default=False, help="Only check permissions with OpenAI", action="store_true")
    parser.add_argument("--only-no-readonly", default=False, help="Only check permissions with OpenAI", action="store_true")
    args = parser.parse_args()

    main(args.profiles, args.api_key, args.verbose, args.only_yaml, args.only_openai, args.only_no_readonly)
