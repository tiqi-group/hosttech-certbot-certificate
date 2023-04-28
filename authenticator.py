#!.venv/bin/python3
"""
Pre-validation hook script for certbot. This script can be specified with the
`--manual-auth-hook` flag

```bash
sudo certbot certonly --manual --preferred-challenges=dns --manual-auth-hook <path/to/repository>/authenticator.py -d <your_domain.ch>
```

This will run this script and then attempt the validation. Additionally, Certbot will
pass relevant environment variables to this script:

CERTBOT_DOMAIN: The domain being authenticated
CERTBOT_VALIDATION: The validation string
CERTBOT_TOKEN: Resource name part of the HTTP-01 challenge (HTTP-01 only)
CERTBOT_REMAINING_CHALLENGES: Number of challenges remaining after the current challenge
CERTBOT_ALL_DOMAINS: A comma-separated list of all domains challenged for the current
certificate
"""

from datetime import datetime
import os
import json
import re
from typing import Union
from loguru import logger
import requests
from dotenv import load_dotenv
import time
import sys

# Add a new sink that only shows INFO level messages
# Logging things when used as autentification hook in certbot will be interpreted as
# error
logger.remove()  # Remove any previously added sinks
logger.add(sys.stdout, level="INFO")

# load environment variables from .env file
load_dotenv()

# API Token from hosttech.eu
API_TOKEN = os.getenv("API_TOKEN")
if API_TOKEN is None:
    raise ValueError(
        "API_TOKEN environment variable is not set. Either set the API_TOKEN "
        "as environment variable or put it into the .env file."
    )
WAIT_TIME = os.getenv("WAIT_TIME", 90)


def get_domain_and_subdomain(domain_str: str) -> tuple[str, Union[str, None]]:
    """Extracts the domain and subdomain from a given domain string.

    Args:
        domain_str (str): A string containing a domain and optional subdomain.

    Returns:
        A tuple containing the domain and subdomain. If no subdomain is present,
        the subdomain value will be None.

    Example:
        >>> get_domain_and_subdomain("example.com")
        ('example.com', None)
        >>> get_domain_and_subdomain("grafana.example.com")
        ('example.com', 'grafana')
    """

    domain_regex = r"(.*)\.([^.]+\.[^.]+)$"
    domain_match = re.search(domain_regex, domain_str)

    if domain_match:
        subdomain = domain_match.group(1)
        domain = domain_match.group(2)
        return domain, subdomain
    else:
        return domain_str, None


def get_txt_record_name_from_domain(domain_str: str) -> str:
    """
    Returns the TXT record name used to verify a domain with Let's Encrypt using DNS-01
    challenge.

    Args:
        domain_str (str): A string containing a domain and optional subdomain.

    Returns:
        A string containing the TXT record name used to verify the domain.

    Example:
        >>> get_txt_record_name_from_domain("example.com")
        '_acme-challenge'
        >>> get_txt_record_name_from_domain("grafana.example.com")
        '_acme-challenge.grafana'
    """

    _, subdomain = get_domain_and_subdomain(domain_str)
    txt_record_name = "_acme-challenge"
    if subdomain is not None:
        txt_record_name += f".{subdomain}"

    return txt_record_name


HOSTTECH_API_URL = "https://api.ns1.hosttech.eu/"
HEADERS_GET = {"accept": "application/json", "Authorization": "Bearer " + API_TOKEN}
HEADERS_POST = {
    "accept": "application/json",
    "Authorization": "Bearer " + API_TOKEN,
    "Content-Type": "application/json",
}
HEADERS_DELETE = {"accept": "*/*", "Authorization": "Bearer " + API_TOKEN}
CERTBOT_DOMAIN = os.getenv("CERTBOT_DOMAIN")
CERTBOT_VALIDATION = os.getenv("CERTBOT_VALIDATION")
CERTBOT_REMAINING_CHALLENGES = os.getenv("CERTBOT_REMAINING_CHALLENGES")
CERTBOT_ALL_DOMAINS = os.getenv("CERTBOT_ALL_DOMAINS")

DOMAIN = get_domain_and_subdomain(CERTBOT_DOMAIN)[0]
TXT_RECORD_NAME = get_txt_record_name_from_domain(CERTBOT_DOMAIN)
RECORDS_API_URL = f"{HOSTTECH_API_URL}/api/user/v1/zones/{DOMAIN}/records"

query_params = {"type": "TXT"}
get_response = requests.get(RECORDS_API_URL, params=query_params, headers=HEADERS_GET)

if get_response.status_code == 200:
    # reverse the order of the lines in the response and parse the JSON data
    data = json.loads("\n".join(get_response.text.strip().split("\n")[::-1]))["data"]

    # Replace any record with the same TXT_RECORD_NAME
    for i in range(len(data)):
        txt_record_name = data[i]["name"]
        txt_record_text = data[i]["text"]
        if txt_record_name == TXT_RECORD_NAME:
            txt_record_id = data[i]["id"]
            delete_response = requests.delete(
                f"{RECORDS_API_URL}/{txt_record_id}", headers=HEADERS_DELETE
            )
            if delete_response.status_code == 204:
                logger.debug(
                    f"Deleted TXT record with name {txt_record_name} and text "
                    f"{txt_record_text} (id {txt_record_id})."
                )
            else:
                logger.error(
                    f"Error: {delete_response.status_code} - {delete_response.text}"
                )

    data = {
        "type": "TXT",
        "name": f"{TXT_RECORD_NAME}",
        "text": f"{CERTBOT_VALIDATION}",
        "ttl": 600,
        "comment": f"Pushed at {datetime.now()}",
    }
    post_response = requests.post(RECORDS_API_URL, headers=HEADERS_POST, json=data)
    if post_response.status_code == 201:
        logger.debug(
            f"Created TXT record with name {TXT_RECORD_NAME} and text {CERTBOT_VALIDATION}."
        )
    else:
        logger.error(f"Error: {post_response.status_code} - {post_response.text}")
else:
    logger.error(f"Error: {get_response.status_code} - {get_response.text}")

time.sleep(WAIT_TIME)
