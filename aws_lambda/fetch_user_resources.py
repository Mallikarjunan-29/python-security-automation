import json
import boto3
from datetime import datetime, date

# Convert all datetime objects to ISO strings
def sanitize(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    return obj

def lambda_handler(event, context):
    username = event.get("UserName")
    if not username:
        return {"statusCode": 400, "body": "Missing UserName"}

    iam = boto3.client("iam")

    def safe(fn, **kwargs):
        try:
            return fn(**kwargs)
        except Exception:
            return None

    login_profile      = safe(iam.get_login_profile, UserName=username)
    access_keys        = safe(iam.list_access_keys, UserName=username)
    mfa_devices        = safe(iam.list_mfa_devices, UserName=username)
    attached_policies  = safe(iam.list_attached_user_policies, UserName=username)
    groups             = safe(iam.list_groups_for_user, UserName=username)
    ssh_keys           = safe(iam.list_ssh_public_keys, UserName=username)
    git_keys           = safe(iam.list_service_specific_credentials, UserName=username)
    signing_certs      = safe(iam.list_signing_certificates, UserName=username)
    user_policies      = safe(iam.list_user_policies, UserName=username)
    user_tags          = safe(iam.list_user_tags, UserName=username)
    user_info          = safe(iam.get_user, UserName=username)

    raw_virtual = safe(iam.list_virtual_mfa_devices, AssignmentStatus="Any")
    if raw_virtual:
        virtual_mfa = [
            x for x in raw_virtual.get("VirtualMFADevices", [])
            if x.get("User", {}).get("UserName") == username
        ]
    else:
        virtual_mfa = None

    response = {
        "statusCode": 200,
        "login_profile": (login_profile or {}).get("LoginProfile"),
        "access_keys": (access_keys or {}).get("AccessKeyMetadata", []),
        "mfa_devices": (mfa_devices or {}).get("MFADevices", []),
        "attached_policies": (attached_policies or {}).get("AttachedPolicies", []),
        "groups": (groups or {}).get("Groups", []),
        "ssh_keys": (ssh_keys or {}).get("SSHPublicKeys", []),
        "git_keys": (git_keys or {}).get("ServiceSpecificCredentials", []),
        "signing_certs": (signing_certs or {}).get("Certificates", []),
        "user_policies": (user_policies or {}).get("PolicyNames", []),
        "user_tags": (user_tags or {}).get("Tags", []),
        "virtual_mfa": virtual_mfa,
        "user_info": (user_info or {}).get("User"),
    }

    # SANITIZE ENTIRE RESPONSE
    return sanitize(response)
