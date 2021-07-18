"""
Original source code from AWS blog by Warren Paull.

For more information, look at this blog
https://aws.amazon.com/blogs/storage/enable-password-authentication-for-aws-transfer-family-using-aws-secrets-manager-updated/
"""

import base64
import json
import logging
import os
from ipaddress import ip_address, ip_network

import boto3
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    # Get the required parameters
    required_param_list = ["serverId", "username", "protocol", "sourceIp"]
    for parameter in required_param_list:
        if parameter not in event:
            logging.info(f"Incoming {parameter} missing - Unexpected")
            return {}

    input_serverId = event["serverId"]
    input_username = event["username"]
    input_protocol = event["protocol"]
    input_sourceIp = event["sourceIp"]
    input_password = event.get("password", "")

    logging.info(
        f"ServerId: {input_serverId}, "
        f"Username: {input_username}, "
        f"Protocol: {input_protocol}, "
        f"SourceIp: {input_sourceIp}"
    )

    # Check for password and set authentication type appropriately. No password means SSH auth
    logging.info("Start User Authentication Flow")
    if input_password != "":
        logging.info("Using PASSWORD authentication")
        authentication_type = "PASSWORD"
    else:
        logging.info("Using SSH authentication")
        authentication_type = "SSH"

    # Retrieve our user details from the secret. For all key-value pairs stored in SecretManager,
    # checking the protocol-specified secret first, then use generic ones.
    # e.g. If SFTPPassword and Password both exists, will be using SFTPPassword for authentication
    secret = get_secret(f"{input_serverId}/{input_username}")

    if secret is not None:
        secret_dict = json.loads(secret)
        # Run our password checks
        user_authenticated = authenticate_user(authentication_type, secret_dict, input_password, input_protocol)
        # Run sourceIp checks
        ip_match = check_ipaddress(secret_dict, input_sourceIp, input_protocol)

        if user_authenticated and ip_match:
            logging.info(f"User authenticated, calling build_response with: {authentication_type}")
            return build_response(secret_dict, authentication_type, input_protocol)
        else:
            logging.info("User failed authentication return empty response")
            return {}
    else:
        # Otherwise something went wrong. Most likely the object name is not there
        logging.info("Secrets Manager exception thrown - Returning empty response")
        # Return an empty data response meaning the user was not authenticated
        return {}


def lookup(secret_dict, key, input_protocol):
    if input_protocol + key in secret_dict:
        logging.info(f"Found protocol-specified {key}")
        return secret_dict[input_protocol + key]
    else:
        return secret_dict.get(key, None)


def check_ipaddress(secret_dict, input_sourceIp, input_protocol):
    accepted_ip_network = lookup(secret_dict, "AcceptedIpNetwork", input_protocol)
    if not accepted_ip_network:
        # No IP provided so skip checks
        logging.info("No IP range provided - Skip IP check")
        return True

    net = ip_network(accepted_ip_network)
    if ip_address(input_sourceIp) in net:
        logging.info("Source IP address match")
        return True
    else:
        logging.info("Source IP address not in range")
        return False


def authenticate_user(auth_type, secret_dict, input_password, input_protocol):
    # Function returns True if: auth_type is password and passwords match or auth_type is SSH. Otherwise returns False
    if auth_type == "SSH":
        # Place for additional checks in future
        logging.info("Skip password check as SSH login request")
        return True
    # auth_type could only be SSH or PASSWORD
    else:
        # Retrieve the password from the secret if exists
        password = lookup(secret_dict, "Password", input_protocol)
        if not password:
            logging.info("Unable to authenticate user - No field match in Secret for password")
            return False

        if input_password == password:
            return True
        else:
            logging.info("Unable to authenticate user - Incoming password does not match stored")
            return False


# Build out our response data for an authenticated response
def build_response(secret_dict, auth_type, input_protocol):
    response_data = {}
    # Check for each key value pair. These are required so set to empty string if missing
    role = lookup(secret_dict, "Role", input_protocol)
    if role:
        response_data["Role"] = role
    else:
        logging.info("No field match for role - Set empty string in response")
        response_data["Role"] = ""

    # These are optional so ignore if not present
    policy = lookup(secret_dict, "Policy", input_protocol)
    if policy:
        response_data["Policy"] = policy

    # External Auth providers support chroot and virtual folder assignments so we'll check for that
    home_directory_details = lookup(secret_dict, "HomeDirectoryDetails", input_protocol)
    if home_directory_details:
        logging.info(
            "HomeDirectoryDetails found - Applying setting for virtual folders\n"
            "Note: Cannot be used in conjunction with key: HomeDirectory"
        )
        response_data["HomeDirectoryDetails"] = home_directory_details
        # If we have a virtual folder setup then we also need to set HomeDirectoryType to "Logical"
        logging.info("Setting HomeDirectoryType to LOGICAL")
        response_data["HomeDirectoryType"] = "LOGICAL"

    # Note that HomeDirectory and HomeDirectoryDetails / Logical mode
    # can't be used together but we're not checking for this
    home_directory = lookup(secret_dict, "HomeDirectory", input_protocol)
    if home_directory:
        logging.info("HomeDirectory found - Note: Cannot be used in conjunction with key: HomeDirectoryDetails")
        response_data["HomeDirectory"] = home_directory

    if auth_type == "SSH":
        public_key = lookup(secret_dict, "PublicKey", input_protocol)
        if public_key:
            response_data["PublicKeys"] = [public_key]
        else:
            # SSH Auth Flow - We don't have keys so we can't help
            logging.info("Unable to authenticate user - No public keys found")
            return {}

    return response_data


def get_secret(id):
    region = os.environ["SecretsManagerRegion"]
    logging.info(f"Secrets Manager Region: {region}")
    logging.info(f"Secret Name: {id}")

    # Create a Secrets Manager client
    client = boto3.session.Session().client(service_name="secretsmanager", region_name=region)

    try:
        resp = client.get_secret_value(SecretId=id)
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if "SecretString" in resp:
            logging.info("Found Secret String")
            return resp["SecretString"]
        else:
            logging.info("Found Binary Secret")
            return base64.b64decode(resp["SecretBinary"])
    except ClientError as err:
        logging.info(
            f'Error Talking to SecretsManager: {err.response["Error"]["Code"]}, '
            f'Message: {err.response["Error"]["Message"]}'
        )
        return None
