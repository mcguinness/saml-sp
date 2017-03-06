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

`npm install`

## Usage

### Static IdP Configuration

`node app.js --idpSsoUrl {url} --cert {pem} --iss {issuer}`

#### Example

`app.js --idpSsoUrl https://example.okta.com/app/example_saml_2/exknnoOGPcwWSnKUK0g3/sso/saml --cert ./idp-cert.pem --iss http://www.okta.com/exknnoOGPcwWSnKUK0g3`

### Dynamic IdP Configuration from SAML IdP Metadata

`node app.js --idpMetaUrl {url}`

#### Example

`node app.js --idpMetaUrl https://example.okta.com/app/exkikd6nFJIdpcrZR0g3/sso/saml/metadata`

### Options

`node app.js  --help`

```
Options:
  --port, -p                Web Server listener port  [number] [required] [default: 7070]
  --issuer, --iss           SP Issuer URI  [string] [required] [default: "urn:example:sp"]
  --audience, --aud         SP Audience URI  [string] [default: "urn:example:sp"]
  --idpSsoUrl               IdP SSO Assertion Consumer URL (SSO URL)  [string]
  --idpSloUrl               IdP Single Logout Assertion Consumer URL (SLO URL)  [string]
  --idpCert, --cert         IdP Signing Certificate (PEM)  [string]
  --idpMetaUrl              IdP SAML Metadata URL  [string]
  --spPrivateKey            SP Request Signature Private Key (pem)  [string] [default: "./server-key.pem"]
  --idFormat                Assertion Subject NameID Format  [string] [default: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
  --httpsPrivateKey, --key  Web Server TLS/SSL Private Key (pem)  [string]
  --httpsCert, --cert       Web Server TLS/SSL Certificate (pem)  [string]
  --https                   Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)  [boolean] [required] [default: false]
  --help                    Show help  [boolean]

Examples:
    app.js --idpSsoUrl https://example.okta.com/app/example_saml_2/exk7s3gpHWyQaKyFx0g4/sso/saml --cert ./idp-cert.pem  Static IdP configuration
    app.js --idpMetaUrl https://example.okta.com/app/exknnoOGPcwWSnKUK0g3/sso/saml/metadata                             Dynamic IdP configuration with SAML Metadata

IdP SAML Metadata URL (idpMetaUrl) or IdP SSO Assertion Consumer URL (idpSsoUrl) and IdP Signing Certificate (cert) is required!
```

## Identity Provider Settings for Service Provider

You need to create a SAML trust in your SAML IdP for the SP web app.  The following settings are required and can be customized via command-line arguments or within the `/settings` page.

Parameter                                      | Description
---------------------------------------------- | --------------------------------------------------------
Assertion Consumer Service URL (POST Binding)  | `http://localhost:7070/saml/sso`
Audience                                       | `urn:example:sp`

## Service Provider Settings

The following settings can be customized at runtime within the `/settings` page:

- Issuer
- Authentication Request Binding
- Sign Authentication Request
- Request/Response Signature Algorithm
- Request Authentication Context Class
- Requested Authentication Context Class
- Skip Authentication Request Compression
- Assertion Validation Clock Skew (Ms)

#  URL Routes

The SP web app hosts the following URL routes:

Route       | Description
----------- | --------------------------------------------------------
`/profile`  | Displays the user profile for the authenticated user
`/login`    | Initiates a SAML SSO request to the IdP
`/logout`   | Attempts to logout via SAML SLO if configured otherwise just destroys the user's active session
`/settings` | Service providers settings
`/saml/sso` | SSO Assertion Consumer endpoint
`/saml/slo` | SLO endpoint

