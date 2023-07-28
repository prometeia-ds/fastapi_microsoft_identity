from typing import Dict

import httpx
from jose import jwt
from lru import LRU

from fastapi_microsoft_identity.model import AuthError


def __handle_azure_ad_key(oauth_key_dict: Dict) -> Dict:
    return {
        "kty": oauth_key_dict["kty"],
        "kid": oauth_key_dict["kid"],
        "use": oauth_key_dict["use"],
        "n": oauth_key_dict["n"],
        "e": oauth_key_dict["e"],
    }


def __handle_b2c_key(oauth_key_dict: Dict) -> Dict:
    return {
        "kid": oauth_key_dict["kid"],
        "kty": oauth_key_dict["kty"],
        "n": oauth_key_dict["n"],
        "e": oauth_key_dict["e"],
        "nbf": oauth_key_dict["nbf"],
    }


async def __helper_extract_azure_key(
    token, oauth_keys_url: str, key_cache: LRU, key_handler
):
    unverified_header = jwt.get_unverified_header(token)

    if unverified_header["kid"] in key_cache:
        return key_cache[unverified_header["kid"]]
    else:
        async with httpx.AsyncClient() as client:
            resp: httpx.Response = await client.get(oauth_keys_url)
            if resp.status_code != 200:
                raise AuthError("Problem with Azure AD discovery URL", status_code=404)

            jwks = resp.json()

            rsa_key = {}
            for key in jwks["keys"]:
                if key["kid"] == unverified_header["kid"]:
                    rsa_key = key_handler(key)
                    key_cache[unverified_header["kid"]] = rsa_key
            return None


async def extract_signing_key_from_ad_token(token, oauth_keys_url: str, key_cache: LRU):
    return await __helper_extract_azure_key(
        token, oauth_keys_url, key_cache, __handle_azure_ad_key
    )


async def extract_signing_key_from_b2c_token(
    token, oauth_keys_url: str, key_cache: LRU
):
    return await __helper_extract_azure_key(
        token, oauth_keys_url, key_cache, __handle_b2c_key
    )
