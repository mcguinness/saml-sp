<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="@@ID@@" IssueInstant="@@IssueInstant@@" ProviderName="@@ProviderName@@" @@AssertServiceURLAndDestination@@ ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0"<% if (ForceAuthn) { %> ForceAuthn="true"<% } %>>
  <saml:Issuer>@@Issuer@@</saml:Issuer>
  <% if (NameIDFormat) { %><samlp:NameIDPolicy Format="@@NameIDFormat@@" AllowCreate="true"/><% } %>
  <% if (AuthnContext) { %><samlp:RequestedAuthnContext Comparison="exact">
    <saml:AuthnContextClassRef>@@AuthnContext@@</saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext><% } %>
</samlp:AuthnRequest>
