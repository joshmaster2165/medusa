"""Patterns for detecting authentication and authorization configuration issues."""

from __future__ import annotations

# General authentication configuration keys
AUTH_CONFIG_KEYS: set[str] = {
    "auth",
    "authentication",
    "authorization",
    "oauth",
    "oidc",
    "jwt",
    "token",
    "api_key",
    "apikey",
    "bearer",
    "credentials",
    "login",
    "saml",
    "sso",
}

# OAuth-specific configuration keys
OAUTH_CONFIG_KEYS: set[str] = {
    "client_id",
    "client_secret",
    "redirect_uri",
    "grant_type",
    "scope",
    "code_challenge",
    "code_verifier",
    "pkce",
    "authorization_endpoint",
    "token_endpoint",
}

# JWT-specific configuration keys
JWT_CONFIG_KEYS: set[str] = {
    "algorithm",
    "alg",
    "secret",
    "signing_key",
    "public_key",
    "private_key",
    "issuer",
    "audience",
    "expiration",
    "exp",
    "nbf",
    "iat",
}

# Cookie security attribute names
COOKIE_SECURITY_FLAGS: set[str] = {
    "secure",
    "httponly",
    "samesite",
    "domain",
    "path",
    "max-age",
    "expires",
}

# CSRF protection configuration keys
CSRF_CONFIG_KEYS: set[str] = {
    "csrf",
    "xsrf",
    "csrf_token",
    "xsrf_token",
    "anti_forgery",
    "csrf_protection",
    "csrf_header",
}

# Multi-factor authentication configuration keys
MFA_CONFIG_KEYS: set[str] = {
    "mfa",
    "2fa",
    "totp",
    "two_factor",
    "multi_factor",
    "otp",
    "authenticator",
}

# JWT algorithms considered weak or insecure
WEAK_JWT_ALGORITHMS: set[str] = {
    "none",
    "HS256",
}

# HTTP header names used for authentication
AUTH_HEADER_NAMES: set[str] = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
}
