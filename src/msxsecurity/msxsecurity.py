#
# Copyright (c) 2021 Cisco Systems, Inc and its affiliates
# All rights reserved
#
import base64
import http.client
import json
import sys

import urllib3
from cachetools import TTLCache


class MSXSecurityContext:
    def __init__(self, data: str):
        if not data:
            raise ValueError("msxsecurity: invalid security context")
        self._json = json.loads(data)

    @property
    def tenant_id(self):
        return self._json["tenant_id"]

    @property
    def assigned_tenants(self):
        return self._json["assigned_tenants"]

    @property
    def permissions(self):
        return self._json["permissions"]

    @property
    def active(self):
        return self._json["active"]


class MSXSecurityConfig:
    def __init__(self,
                 sso_url: str,
                 client_id: str,
                 client_secret: str,
                 cache_enabled=False,
                 cache_ttl_seconds=300):
        self.sso_url = sso_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.cache_enabled = cache_enabled
        self.cache_ttl_seconds = cache_ttl_seconds


class MSXSecurity:
    def __init__(self, config: MSXSecurityConfig):
        self._http = None
        self._cache = None
        self._config = config

        if not config.client_id:
            sys.stderr.write("msxsecurity: client id cannot be empty")
        elif not config.client_secret:
            sys.stderr.write("msxsecurity: client secret cannot be empty")
        else:
            # Write the HTTP headers.
            basic_token = base64.b64encode(str.encode(self._config.client_id + ":" + self._config.client_secret))
            basic_authorization = "Basic " + basic_token.decode()
            headers = {
                "Connection": "close",
                "Authorization": basic_authorization,
                "Accept": "application/json",
            }

            # Create the HTTP pool and configure the cache.
            self._http = urllib3.PoolManager(headers=headers, cert_reqs='CERT_NONE')
            if config.cache_enabled:
                self._cache = TTLCache(maxsize=1024, ttl=config.cache_ttl_seconds)

    def clear_cache(self):
        if self._cache:
            self._cache.clear()

    def check_token(self, access_token: str, force_refresh=False):
        # Check the cache first.
        if not force_refresh and self._cache and access_token in self._cache:
            return self._cache.get(access_token)

        # Exchange the MSX access token for an MSX security context.
        check_token_url = "%s/v2/check_token?token_type_hint=access_token" % self._config.sso_url
        response = self._http.request_encode_body(
            "POST",
            check_token_url,
            fields={"token": access_token},
            encode_multipart=False)

        # Check and return the response caching if configured.
        if response.status == http.HTTPStatus.OK:
            security_context = MSXSecurityContext(response.data)
            if self._cache is not None:
                self._cache[access_token] = security_context
            return security_context
        sys.stderr.write("msx check token request failed\n")
        return None

    def has_permission(self, permission: str, access_token: str, force_refresh=False):
        security_context = self.check_token(access_token, force_refresh)
        return security_context \
            and security_context.active \
            and security_context.permissions \
            and permission in security_context.permissions

    def has_tenant(self, tenant_id: str, access_token: str, force_refresh=False):
        security_context = self.check_token(access_token, force_refresh)
        return security_context \
            and security_context.active \
            and security_context.assigned_tenants \
            and tenant_id in security_context.assigned_tenants
