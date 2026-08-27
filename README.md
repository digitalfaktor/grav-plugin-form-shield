# Form Shield

Form Shield is a privacy-conscious spam-protection plugin for Grav forms. It layers several local checks so that no third-party CAPTCHA provider is required (GDPR Compliant).

## Features

- Automatically adds a honeypot field to protected forms.
- Adds the local Cap proof-of-work CAPTCHA supplied by the Grav Form plugin.
- Rejects forms submitted unrealistically quickly after rendering.
- Limits submissions per IP address within a configurable time window.
- Preserves manually configured CAPTCHA and honeypot fields instead of adding duplicates.

Cap runs locally in the visitor's browser and validates against the website itself.

## Requirements

- Grav 2.0 or newer
- PHP 8.1 or newer
- Form plugin 9.1.23 or newer

## Installation

Copy the `form-shield` directory into `user/plugins/` or install the packaged ZIP through Grav's Plugin Admin. By default, every form is protected.

```yaml
enabled: true
routes:
  - /contact
```

Leave `routes` empty to protect every Grav form on the site. Select one or more pages only when you want to limit protection to forms on those pages. Clear the Grav cache after changing routes so the form definition is rebuilt.

## Configuration

```yaml
honeypot:
  enabled: true

captcha:
  enabled: true
  mode: invisible # invisible or checkbox

time_check:
  enabled: true
  minimum_seconds: 5
  maximum_age_seconds: 7200

rate_limit:
  enabled: true
  maximum_attempts: 3
  window_seconds: 600

failure_response:
  mode: message # message or silent
  message: 'We could not process your submission. Please try again.'
```

The honeypot, CAPTCHA, and validation action are injected for every form by default, or only for forms on selected pages when `routes` is populated. This includes both `form` and `forms` page definitions. If a protected form already defines a CAPTCHA or honeypot, Form Shield leaves that field in place and does not duplicate it.

## Security failure response

Use `failure_response.mode: message` to show the configured general message at the form when Form Shield rejects a submission. This is the default and is appropriate when a real visitor could need to retry a CAPTCHA check.

Use `failure_response.mode: silent` to return the form without displaying a security-specific message. The rejected submission is never processed or emailed. Normal form validation messages, such as a missing required email address, are unaffected.

Themes that provide their own form layout should render Grav's `partials/form-messages.html.twig` partial and use the active `form` variable after a submission. Grav's default form template already does both.

## Privacy notes

The timing check stores a form start timestamp in the visitor's server-side session. The rate limiter stores only a SHA-256 hash of the IP address and recent timestamps in Grav's cache. Neither check sends data to a third party.

Each site operator remains responsible for documenting the relevant processing in their privacy notice and selecting an appropriate retention period. This plugin is not legal advice.

## Operational limits

The rate limiter is an application-level layer and is deliberately simple. For a sustained attack, add a rate limit at the web server, reverse proxy, or firewall as well.
