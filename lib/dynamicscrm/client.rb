require 'httparty'
require 'uuid'
require 'awesome_print'
require 'nokogiri'

module DynamicsCRM
  class Parser < HTTParty::Parser
    SupportedFormats = {
      'application/soap+xml; charset=UTF-8' => :dynamicsxml
    }
    def dynamicsxml
      Nokogiri::XML(body)
    end
  end

  class Client
    include HTTParty
    parser Parser
    format :dynamicsxml

    def get(*args)
      self.class.get(*args)
    end
    def post(*args)
      self.class.post(*args)
    end
  end
end

client = DynamicsCRM::Client.new

config = YAML.load_file('config.yml')

crm_url = config['url']
wsdl = client.get("#{crm_url}?wsdl")
wsdl_import_url = wsdl.xpath("//*[local-name()='import' and namespace-uri()='http://schemas.xmlsoap.org/wsdl/']/@location").inner_text
wsdk_import = client.get(wsdl_import_url)
urn_address = wsdk_import.xpath("//*[local-name()='AuthenticationPolicy' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']/*[local-name()='SecureTokenService' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']//*[local-name()='AppliesTo' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']/text()").inner_text
p urn_address
sts_endpoint = wsdk_import.xpath("//*[local-name()='Issuer' and namespace-uri()='http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702']/*[local-name()='Address' and namespace-uri()='http://www.w3.org/2005/08/addressing']/text()").inner_text

current_time_f = Time.now.to_f
time_created = Time.at(current_time_f).utc.strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}Z"
time_expires = Time.at(current_time_f + 5*60).utc.strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}Z"
security_token_soap_request = "
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
    xmlns:a=\"http://www.w3.org/2005/08/addressing\"
    xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">
    <s:Header>
        <a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:MessageID>urn:uuid:#{UUID.generate}</a:MessageID>
        <a:ReplyTo> <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address> </a:ReplyTo>
        <VsDebuggerCausalityData xmlns=\"http://schemas.microsoft.com/vstudio/diagnostics/servicemodelsink\">uIDPo4TBVw9fIMZFmc7ZFxBXIcYAAAAAbd1LF/fnfUOzaja8sGev0GKsBdINtR5Jt13WPsZ9dPgACQAA </VsDebuggerCausalityData>
        <a:To s:mustUnderstand=\"1\">#{sts_endpoint}</a:To>
        <o:Security s:mustUnderstand=\"1\"
            xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">
            <u:Timestamp u:Id=\"_0\"> <u:Created>#{time_created}</u:Created> <u:Expires>#{time_expires}</u:Expires> </u:Timestamp>
            <o:UsernameToken u:Id=\"uuid-14bed392-2320-44ae-859d-fa4ec83df57a-1\">
                <o:Username>#{config['username']}</o:Username>
                <o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">#{config['password']}</o:Password>
            </o:UsernameToken>
        </o:Security>
    </s:Header>
    <s:Body>
        <t:RequestSecurityToken xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">
            <wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\">
                <a:EndpointReference>
                    <a:Address>#{urn_address}</a:Address>
                </a:EndpointReference>
            </wsp:AppliesTo>
            <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue
            </t:RequestType>
        </t:RequestSecurityToken>
    </s:Body>
</s:Envelope>
"

security_token_response = client.post(sts_endpoint, { headers: {'Content-Type' => 'application/soap+xml; charset=UTF-8'}, body: security_token_soap_request })

security_token0, security_token1 = security_token_response.xpath("//*[local-name()='CipherValue']/text()").to_a.map(&:inner_text)
key_identifier = security_token_response.xpath("//*[local-name()='KeyIdentifier']/text()").to_a.first.inner_text


time_created = Time.at(current_time_f).utc.strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}Z"
time_expires = Time.at(current_time_f + 5*60).utc.strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}Z"
retrieve_request_soap_template = "
    <s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">
      <s:Header>
        <a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/#{'Retrieve'}</a:Action>
        <a:MessageID>urn:uuid:#{UUID.generate}</a:MessageID>
        <a:ReplyTo>
          <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <VsDebuggerCausalityData xmlns=\"http://schemas.microsoft.com/vstudio/diagnostics/servicemodelsink\">
        uIDPozJEz+P/wJdOhoN2XNauvYcAAAAAK0Y6fOjvMEqbgs9ivCmFPaZlxcAnCJ1GiX+Rpi09nSYACQAA</VsDebuggerCausalityData>
        <a:To s:mustUnderstand=\"1\">#{crm_url}</a:To>
        <o:Security s:mustUnderstand=\"1\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">
          <u:Timestamp u:Id=\"_0\">
            <u:Created>#{time_created}</u:Created>
            <u:Expires>#{time_expires}</u:Expires>
          </u:Timestamp>
          <EncryptedData Id=\"Assertion0\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"
          xmlns=\"http://www.w3.org/2001/04/xmlenc#\">
            <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\">
            </EncryptionMethod>
            <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">
              <EncryptedKey>
                <EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">
                </EncryptionMethod>
                <ds:KeyInfo Id=\"keyinfo\">
                  <wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">
                    <wsse:KeyIdentifier EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\">#{key_identifier}</wsse:KeyIdentifier>
                  </wsse:SecurityTokenReference>
                </ds:KeyInfo>
                <CipherData>
                  <CipherValue>#{security_token0}</CipherValue>
                </CipherData>
              </EncryptedKey>
            </ds:KeyInfo>
            <CipherData>
              <CipherValue>#{security_token1}</CipherValue>
            </CipherData>
          </EncryptedData>
        </o:Security>
      </s:Header>
      <s:Body>
    <Retrieve xmlns=\"http://schemas.microsoft.com/xrm/2011/Contracts/Services\">
      <entityName>account</entityName>
      <id>#{config['account_id']}</id>
      <columnSet xmlns:b=\"http://schemas.microsoft.com/xrm/2011/Contracts\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">
        <b:AllColumns>false</b:AllColumns>
        <b:Columns xmlns:c=\"http://schemas.microsoft.com/2003/10/Serialization/Arrays\">
          <c:string>name</c:string>
          <c:string>address1_postalcode</c:string>
          <c:string>lastusedincampaign</c:string>
        </b:Columns>
      </columnSet>
    </Retrieve>
  </s:Body>
</s:Envelope>"

retrieve_response_xml = client.post(crm_url, headers: {'Content-Type' => 'application/soap+xml; charset=UTF-8'}, body: retrieve_request_soap_template)

namespaces = {
  b: "http://schemas.microsoft.com/xrm/2011/Contracts",
  c: "http://schemas.datacontract.org/2004/07/System.Collections.Generic"
}

account_name = retrieve_response_xml.xpath("//b:KeyValuePairOfstringanyType[c:key='name']/c:value/text()", namespaces).inner_text
zipcode = retrieve_response_xml.xpath("//b:KeyValuePairOfstringanyType[c:key='address1_postalcode']/c:value/text()", namespaces).inner_text


ap(
  account_name: account_name,
  zipcode: zipcode
)
