# Changelog

# 1.0.2

## 2026-08-31

1. [](#improved)
   * Generate timing tokens for each form instance instead of caching them with the form definition.
   * Scope rate limits to the submitting IP address and form route.
   * Apply the configured failure response to Form Shield honeypot failures.
   * Skip Form Shield processing in CLI requests.

# 1.0.1

## 2026-08-28

1. [](#security)
   * Replaced the session-based timing check with a signed, stateless timestamp.
   * Use Grav's guarded client IP resolver for rate limiting and cap stored attempts.
   * Derive the injected honeypot field name from the site's security key.

2. [](#improved)
   * Prevent Form Shield from changing form definitions during Admin2 requests.
   * Added Admin2-compatible route and section fields.
   * Added English translations for plugin settings and default visitor messages.
   * Preserve error messages from manually configured Cap CAPTCHA fields.

# 1.0.0

## 2026-08-27

1. [](#new)
   * Initial release with local Cap CAPTCHA injection, timing checks, and rate limiting.
