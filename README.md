# Introduction

This app provides a simple test Service Provider for [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile)

The following features are supported:

- Authentication Request
-- Signatures (SHA1 or SHA256)
-- HTTP-POST or HTTP-Redirect Bindings
-- Authentication Context Class
-- ForceAuthn
- Assertion Consumer Service
-- HTTP-POST or HTTP-Redirect Bindings
-- Encrypted Assertions
- SAML Single Logout

# Installation

  npm install

## Usage

	`node app.js --idpSsoUrl {url} --cert {pem} --iss {issuer}`
  `node app.js --idpMetaUrl {url}`

### Example

	`node app.js --idpMetaUrl https://example.okta.com/app/exkikd6nFJIdpcrZR0g3/sso/saml/metadata`

## Settings

Service providers settings can be customized at runtime within the `/settings` page

# Default Routes

Route       | Description
----------- | --------------------------------------------------------
`/profile`  | Displays the user profile for the authenticated user
`/login`    | Initiates a SAML SSO request to the IdP
`/logout`   | Attempts to logout via SAML SLO if configured otherwise just destroys the user's active session
`/settings` | Service providers settings
`/saml/sso` | SSO Assertion Consumer endpoint
`/saml/slo` | SLO endpoint

