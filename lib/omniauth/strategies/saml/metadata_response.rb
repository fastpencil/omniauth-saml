module OmniAuth
  module Strategies
    class SAML
      class MetadataResponse
        def create(settings, request = nil, params = {})
          consumer_url = settings[:assertion_consumer_service_url]
          if request && consumer_url.is_a?(Proc)
            consumer_url = consumer_url.call(request)
          end

          response =
              "<?xml version='1.0'?>\n" +
                  "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"#{settings[:issuer]}\">\n" +
                  "<md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
          unless settings[:name_identifier_format].nil?
            response << "<md:NameIDFormat>#{settings[:name_identifier_format]}</md:NameIDFormat>\n"
          end
          response <<
              "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"#{consumer_url}\"/>\n" +
              "</md:SPSSODescriptor>\n" +
              "</md:EntityDescriptor>"
        end
      end
    end
  end
end

