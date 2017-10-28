# Introduction

This app provides a simple test Service Provider (SP) for [SAML 2.0 Web Browser SSO Profile](http://en.wikipedia.org/wiki/SAML_2.0#Web_Browser_SSO_Profile) or Relying Party (RP) for [WS-Federation Passive Requestor Profile](http://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html#_Toc223175002)

The following SAML 2.0 WebSSO features are supported:

- Authentication Request
  - Signatures (SHA1 or SHA256)
  - HTTP-POST or HTTP-Redirect Bindings
- Authentication Context Class
  - NameID Format
  - ForceAuthn
  - Dynamic AssertionConsumerServiceURL
- Assertion Consumer Service
  - Signature Verification with Public Key Certificate or Thumbprint
  - HTTP-POST Binding
  - Encrypted Assertions
- SAML Single Logout Service
  - Signatures (SHA1 or SHA256)
  - HTTP-POST Binding for Responses
  - HTTP-POST or HTTP-Redirect Bindings for Requests
- SAML Metadata
  - Auto-configuration with IdP Metadata
  - Publish SP Metadata

The following WS-Federation features are supported:

- Security Token Service Response
  - Signature Verification with Public Key Certificate or Thumbprint
  - Encrypted Assertions
- Federation Metadata
  - Auto-configuration with IdP Metadata
  - Publish RP Metadata


# Installation

`npm install`

## Usage

### Dynamic IdP Configuration from IdP Metadata (Recommended)

`node bin/server.js --idpMetaUrl {url}`

> The default protocol is SAMLP if metadata supports both SAMLP and WS-Federation

#### Example

`node bin/server.js --idpMetaUrl https://example.okta.com/app/exkikd6nFJIdpcrZR0g3/sso/saml/metadata`

### Static IdP Configuration with Certificate

`node bin/server.js --iss {issuer} --idpSsoUrl {url} --idpCert {pem}`

#### Example

`node bin/server.js --iss http://www.okta.com/exknnoOGPcwWSnKUK0g3 --idpSsoUrl https://example.okta.com/app/example_saml/exknnoOGPcwWSnKUK0g3/sso/saml --idpCert ./idp-cert.pem`

### Static IdP Configuration with SHA1 Thumbprint

`node bin/server.js --iss {issuer} --idpSsoUrl {url} --idpThumbprint {sha1}`

#### Example

`node bin/server.js --iss http://www.okta.com/exknnoOGPcwWSnKUK0g3 --idpSsoUrl https://example.okta.com/app/example_saml/exknnoOGPcwWSnKUK0g3/sso/saml --idpThumbprint 77:87:4A:86:18:B3:CB:44:C2:EB:68:1B:77:0B:1D:F6:4A:0E:88:E7`


### Options

`node bin/server.js  --help`

```
Options:
  --version                      Show version number                                                                                                       [boolean]
  --settings                     Path to JSON config file
  --port, -p                     Web Server listener port                                                                        [number] [required] [default: 7070]
  --protocol                     Federation Protocol                                                                          [string] [required] [default: "samlp"]
  --idpIssuer, --iss             IdP Issuer URI                                                                                [string] [default: "urn:example:idp"]
  --idpSsoUrl                    IdP Single Sign-On Service URL (SSO URL)                                                                                   [string]
  --idpSsoBinding                IdP Single Sign-On AuthnRequest Binding         [string] [required] [default: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]
  --idpSloUrl                    IdP Single Logout Service URL (SLO URL) (SAMLP)                                                                            [string]
  --idpSloBinding                IdP Single Logout Request Binding (SAMLP)       [string] [required] [default: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]
  --idpCert                      IdP Public Key Signing Certificate (PEM)                                                                                   [string]
  --idpThumbprint                IdP Public Key Signing Certificate SHA1 Thumbprint                                                                         [string]
  --idpMetaUrl                   IdP SAML Metadata URL                                                                                                      [string]
  --audience, --aud              SP Audience URI / RP Realm                                                                     [string] [default: "urn:example:sp"]
  --providerName                 SP Provider Name                                                                 [string] [default: "Simple SAML Service Provider"]
  --acsUrls                      SP Assertion Consumer Service (ACS) URLs (Relative URL)                                 [array] [required] [default: ["/saml/sso"]]
  --signAuthnRequests, --signed  Sign AuthnRequest Messages (SAMLP)                                                             [boolean] [required] [default: true]
  --signatureAlgorithm           Signature Algorithm                                                                                [string] [default: "rsa-sha256"]
  --digestAlgorithm              Digest Algorithm                                                                                       [string] [default: "sha256"]
  --requestNameIDFormat          Request Subject NameID Format (SAMLP)                                                                     [boolean] [default: true]
  --validateNameIDFormat         Validate format of Assertion Subject NameID                                                               [boolean] [default: true]
  --nameIDFormat, --nameid       Assertion Subject NameID Format                        [string] [default: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"]
  --requestAuthnContext          Request Authentication Context (SAMLP)                                                                    [boolean] [default: true]
  --authnContextClassRef, --acr  Authentication Context Class Reference      [string] [default: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"]
  --spCert                       SP/RP Public Key Signature & Encryption Certificate (PEM)          [string] [default: "/Users/karl/src/saml-sp/config/sp-cert.pem"]
  --spKey                        SP/RP Private Key Signature & Decryption Certificate(PEM)           [string] [default: "/Users/karl/src/saml-sp/config/sp-key.pem"]
  --httpsPrivateKey              Web Server TLS/SSL Private Key (PEM)                                                                                       [string]
  --httpsCert                    Web Server TLS/SSL Certificate (PEM)                                                                                       [string]
  --https                        Enables HTTPS Listener (requires httpsPrivateKey and httpsCert)                                          [boolean] [default: false]
  --relayState, --rs             Default Relay State                                                                                                        [string]
  --help                         Show help                                                                                                                 [boolean]
```

### Passing key-pairs from environment variables

key-pairs can also be passed from environment variables.

```
node bin/server.js --iss {issuer} --idpSsoUrl {url} --idpCert="$SAML_IDP_CERT" --spCert="$SAML_SP_CERT" --spKey="$SAML_SP_KEY"
```

# SAML 2.0 SSO Protocol

The SAML 2.0 protocol is specified with `--protocol samlp` (default)

## Identity Provider Settings

The IdP settings needed for federation can be auto-configured via IdP SAML Metadata.  If IdP SAML metadata is not available you can manually specify service endpoints, binding, and signing credentials.

> If you need an IdP to test with, use  [Simple Identity Provider (IdP) for SAML 2.0](https://github.com/mcguinness/saml-idp) for all your end-to-end SAML 2.0 Web Browser SSO flows!

### Endpoints

Endpoints               | Argument        | Default
----------------------- | --------------- | --------------------------------------------------------
SSO Service URL         | `idpSsoUrl`     |
SSO Service Binding     | `idpSsoBinding` | `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`
SLO Service  URL        | `idpSloUrl`     |
SLO Service Binding     | `idpSloBinding` | `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`

### Response/Assertion Signing Certificate

You must specify the public key certificate with the `idpCert` or SHA1 thumbprint with `idpThumbprint` argument to validate the SAMLResponse message from the IdP.

## Service Provider Settings

You need to create a SAML trust in your SAML IdP for the SP web app.  The following settings are required and can be customized via command-line arguments or within the `/settings` page.

### Audience (EntityID)

The default SP audience is `urn:example:sp`.  You can change this with the `--aud` argument.

### Binding

The Service Provider only supports the HTTP-POST binding for the Assertion Consumer Service

Service                    | Binding       | URL
-------------------------- | ------------- | --------------------------------------------------------
Assertion Consumer Service | HTTP-POST     | `http://localhost:port/saml/sso` (Default)
Single Logout Service      | HTTP-POST     | `http://localhost:port/saml/slo`

You can specify additional endpoints (relative paths) for the Assertion Consumer Service with the `acsUrls` argument.  The first ACS URL in the array (e.g. acsUrls[0]) is used by default for AuthnRequests.  You can select any configured ACS URL for requests with the `/login?acsUrl=/path` query param or by going to the settings page in the SP and selecting the default ACS URL.

### Request Signing Certificate

You should generate a self-signed certificate for the SP.

    openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Service Provider' -keyout /config/sp-key.pem -out /config/sp-cert.pem -days 7300

This key-pair will be used to sign SAML AuthnRequest and LogoutRequest messages generated by the Service Provider.  You can disable AuthnRequest message signatures with the `signAuthnRequests` argument.  LogoutRequest messages always require signatures.

## Decryption Private Key

The Service Provider uses the same key-pair for signatures and decryption.  Use the same signing public key certificate to encrypt SAML assertion in the IdP.

### SAML Metadata

Service Provider SAML metadata is available on `http://localhost:port/metadata`

# WS-Federation Protocol

The WS-Federation protocol is specified with `--protocol wsfed`

## Identity Provider Settings

The IdP settings needed for federation can be auto-configured via IdP Metadata.  If IdP metadata is not available you can manually specify service endpoints, binding, and signing credentials.


### Endpoints

Endpoints                      | Argument        | Default
------------------------------ | --------------- | --------------------------------------------------------
IdP Passive Requestor Endpoint | `idpSsoUrl`     |

### Assertion Signing Certificate

You must specify the public key certificate with the `idpCert` or SHA1 thumbprint with `idpThumbprint` argument to validate the SAML 2.0 security token returned from the IdP.

## Relying Party Settings

You need to create a federation trust in your IdP/STS for the RP web app.  The following settings are required and can be customized via command-line arguments or within the `/settings` page.

### Realm (Audience)

The default RP realm/audience is `urn:example:sp`.  You can change this with the `--aud` argument.

### Binding

The Relying Party only supports the HTTP-POST binding for the Security Token Response Endpoint

Service                          | Binding       | URL
-------------------------------- | ------------- | --------------------------------------------------------
Security Token Response Endpoint | HTTP-POST     | `http://localhost:port/saml/sso`

## Decryption Private Key

Use the same signing public key certificate to encrypt SAML assertion in the IdP.

### RP Metadata

Relying Party SAML metadata is available on `http://localhost:port/metadata`

# Web Server

You can customize the port and optionally provide a TLS/SSL certificate for the Service Provider to enable HTTPS

##  HTTP URL Routes

The web app hosts the following URL routes:

Route       | Description
----------- | --------------------------------------------------------
`/profile`  | Displays the user profile for the authenticated user
`/login`    | Initiates a SSO request to the IdP
`/logout`   | Attempts to logout via SAML SLO if configured otherwise just destroys the user's active session
`/settings` | Service Providers settings
`/saml/sso` | SSO Assertion Consumer Service / Security Token Service Response Passive Endpoint
`/saml/slo` | SLO endpoint
`/metadata` | Service Provider/Relying Party Metadata endpoint

## HTTPS

Specify the `https` argument to enable TLS along with public key certificate and private key in PEM format

```
node bin/server.js --https --httpsCert {cert} --httpsKey {key}

```
