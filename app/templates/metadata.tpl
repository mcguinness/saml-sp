<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="<%= entityID %>">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate><%= cert %></ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate><%= cert %></ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="<%= sloUrl %>"/>
    <md:NameIDFormat><%= nameIDFormat %></md:NameIDFormat>
    <% for (var i=0; i<acsUrls.length; i++) {%><md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="<%= acsUrls[i] %>" index="<%= i + 1%>"/><% } %>
  </md:SPSSODescriptor>

  <RoleDescriptor xsi:type="fed:ApplicationServiceType" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <fed:TargetScopes>
        <EndpointReference xmlns="http://www.w3.org/2005/08/addressing">
          <Address><%= realm %></Address>
        </EndpointReference>
    </fed:TargetScopes>
    <fed:PassiveRequestorEndpoint>
        <EndpointReference xmlns="http://www.w3.org/2005/08/addressing">
          <Address><%= acsUrls[0] %></Address>
        </EndpointReference>
    </fed:PassiveRequestorEndpoint>
  </RoleDescriptor>

</md:EntityDescriptor>
