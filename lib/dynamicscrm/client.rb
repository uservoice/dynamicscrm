require 'httparty'
require 'awesome_print'


wsdl = HTTParty.get('https://uservoicedev.api.crm.dynamics.com/XRMServices/2011/Organization.svc?wsdl')
wsdl_import_url = wsdl['definitions']['import']['location']
wsdl_import_all_definitions = HTTParty.get(wsdl_import_url)['definitions']['Policy']['ExactlyOne']['All']
urn_address = wsdl_import_all_definitions['AuthenticationPolicy'].first['SecureTokenService']['LiveTrust']['AppliesTo']
sts_endpoint = wsdl_import_all_definitions['SignedSupportingTokens']['Policy']['IssuedToken']['Issuer']['Address']

key_identifier = nil
security_token0 = nil
security_token1 = nil
current_time_f = Time.now.to_f
time_created = Time.at(current_time_f).strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}"
time_expires = Time.at(current_time_f + 5*60).strftime("%Y-%m-%dT%H:%M:%S") + ".#{"%03d" % [(current_time_f-current_time_f.floor)*1000]}"
security_token_soap_template = "
<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"
    xmlns:a=\"http://www.w3.org/2005/08/addressing\"
    xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">
    <s:Header>
        <a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
        <a:MessageID>urn:uuid:#{message_id}</a:MessageID>
        <a:ReplyTo> <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address> </a:ReplyTo>
        <VsDebuggerCausalityData xmlns=\"http://schemas.microsoft.com/vstudio/diagnostics/servicemodelsink\">uIDPo4TBVw9fIMZFmc7ZFxBXIcYAAAAAbd1LF/fnfUOzaja8sGev0GKsBdINtR5Jt13WPsZ9dPgACQAA </VsDebuggerCausalityData>
        <a:To s:mustUnderstand=\"1\">{sts_endpoint}</a:To>
        <o:Security s:mustUnderstand=\"1\"
            xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">
            <u:Timestamp u:Id=\"_0\"> <u:Created>#{time_created}Z</u:Created> <u:Expires>#{time_expires}Z</u:Expires> </u:Timestamp>
            <o:UsernameToken u:Id=\"uuid-14bed392-2320-44ae-859d-fa4ec83df57a-1\">
                <o:Username>#{username}</o:Username>
                <o:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">#{password}</o:Password>
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

ap(urn_address: urn_address, sts_endpoint: sts_endpoint)
