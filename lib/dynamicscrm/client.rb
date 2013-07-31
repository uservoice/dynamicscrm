require 'httparty'
require 'uuid'
require 'awesome_print'
require 'nokogiri'

module DynamicsCRM
  AuthenticationError = Class.new(StandardError)

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

    def initialize(url, username, password)
      @crm_url = url.to_s.split('?').first
      raise AuthenticationError.new('Invalid CRM URL') if @crm_url.nil?
      @username = username
      @password = password
    end

    def get(*args)
      self.class.get(*args)
    end

    def post(*args)
      resp = self.class.post(*args)

      fault_reason = resp.xpath("//s:Fault/s:Reason", {'s' => 'http://www.w3.org/2003/05/soap-envelope'}).inner_text
      unless fault_reason.nil? || fault_reason == ''
        raise DynamicsCRM::AuthenticationError.new(fault_reason)
      end

      resp
    end

    def operation(body)
      operation_name = body[/[A-Za-z]+/]
      self.post(@crm_url, headers: {'Content-Type' => 'application/soap+xml; charset=UTF-8'},
      :body => "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
                            xmlns:a=\"http://www.w3.org/2005/08/addressing\"
                            xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">
                  #{generate_header(operation_name)}
                  <s:Body>
                    #{body}
                  </s:Body>
                </s:Envelope>")
    end

    private
    def request_authentication_tokens
      wsdl = get("#{@crm_url}?wsdl")
      wsdl_import_url = wsdl.xpath("//*[local-name()='import' and namespace-uri()='http://schemas.xmlsoap.org/wsdl/']/@location").inner_text
      wsdk_import = get(wsdl_import_url)
      urn_address = wsdk_import.xpath("//*[local-name()='AuthenticationPolicy' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']/*[local-name()='SecureTokenService' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']//*[local-name()='AppliesTo' and namespace-uri()='http://schemas.microsoft.com/xrm/2011/Contracts/Services']/text()").inner_text
      sts_endpoint = wsdk_import.xpath("//*[local-name()='Issuer' and namespace-uri()='http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702']/*[local-name()='Address' and namespace-uri()='http://www.w3.org/2005/08/addressing']/text()").inner_text

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
                      <o:Username>#{@username}</o:Username>
                      <o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">#{@password}</o:Password>
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
      
      security_token_response = post(sts_endpoint, { headers: {'Content-Type' => 'application/soap+xml; charset=UTF-8'}, body: security_token_soap_request })
      
      @security_token0, @security_token1 = security_token_response.xpath("//*[local-name()='CipherValue']/text()").to_a.map(&:inner_text)
      @key_identifier = security_token_response.xpath("//*[local-name()='KeyIdentifier']/text()").to_a.first.inner_text
    end

    def generate_header(operation)
      request_authentication_tokens
      """
      <s:Header>
        <a:Action s:mustUnderstand=\"1\">http://schemas.microsoft.com/xrm/2011/Contracts/Services/IOrganizationService/#{operation}</a:Action>
        <a:MessageID>urn:uuid:#{UUID.generate}</a:MessageID>
        <a:ReplyTo>
          <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <VsDebuggerCausalityData xmlns=\"http://schemas.microsoft.com/vstudio/diagnostics/servicemodelsink\">
        uIDPozJEz+P/wJdOhoN2XNauvYcAAAAAK0Y6fOjvMEqbgs9ivCmFPaZlxcAnCJ1GiX+Rpi09nSYACQAA</VsDebuggerCausalityData>
        <a:To s:mustUnderstand=\"1\">#{@crm_url}</a:To>
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
                    <wsse:KeyIdentifier EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier\">#{@key_identifier}</wsse:KeyIdentifier>
                  </wsse:SecurityTokenReference>
                </ds:KeyInfo>
                <CipherData>
                  <CipherValue>#{@security_token0}</CipherValue>
                </CipherData>
              </EncryptedKey>
            </ds:KeyInfo>
            <CipherData>
              <CipherValue>#{@security_token1}</CipherValue>
            </CipherData>
          </EncryptedData>
        </o:Security>
      </s:Header>
      """
    end

    def time_created
      current_time_f = Time.now.to_f
      Time.at(current_time_f).utc.strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}Z"
    end

    def time_expires
      current_time_f = Time.now.to_f
      Time.at(current_time_f + 5*60).utc.strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}Z"
    end
  end
end
