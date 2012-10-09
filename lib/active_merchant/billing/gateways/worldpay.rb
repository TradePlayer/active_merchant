module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class WorldpayGateway < Gateway
      self.test_url = 'https://secure-test.worldpay.com/jsp/merchant/xml/paymentService.jsp'
      self.live_url = 'https://secure.worldpay.com/jsp/merchant/xml/paymentService.jsp'

      self.default_currency = 'GBP'
      self.money_format = :cents
      self.supported_countries = ['HK', 'US', 'GB', 'AU']
      self.homepage_url = 'http://www.worldpay.com/'
      self.display_name = 'WorldPay'

      self.supported_cardtypes = [:visa, :master, :american_express, :discover, :jcb, :solo, :maestro, :diners_club, :laser]
      CARD_CODES = {
        'visa'             => 'VISA-SSL',
        'master'           => 'ECMC-SSL',
        'american_express' => 'AMEX-SSL',
        'discover'         => 'DISCOVER-SSL',
        'jcb'              => 'JCB-SSL',
        'solo'             => 'SOLO_GB-SSL',
        'maestro'          => 'MAESTRO-SSL',
        'diners_club'      => 'DINERS-SSL',
        'laser'            => 'LASER-SSL'
      }

      def initialize(options = {})
        requires!(options, :login, :password)
        @options = options
        super
      end

      def purchase(money, payment_method, options = {})
        MultiResponse.new.tap do |r|
          r.process{authorize(money, payment_method, options)}
          r.process{capture(money, r.authorization, options.merge(:authorization_validated => true))}
        end
      end

      def authorize(money, payment_method, options = {})
        requires!(options, :order_id)
        authorize_request(money, payment_method, options)
      end

      def capture(money, authorization, options = {})
        MultiResponse.new.tap do |r|
          r.process{inquire_request(authorization, options, "AUTHORISED")} unless options[:authorization_validated]
          r.process{capture_request(money, authorization, options)}
        end
      end

      def void(authorization, options = {})
        MultiResponse.new.tap do |r|
          r.process{inquire_request(authorization, options, "AUTHORISED")}
          r.process{cancel_request(authorization, options)}
        end
      end

      def refund(money, authorization, options = {})
        MultiResponse.new.tap do |r|
          r.process{inquire_request(authorization, options, "CAPTURED")}
          r.process{refund_request(money, authorization, options)}
        end
      end

      def payout_to_visa(money, payment_method, options = {})
        MultiResponse.new.tap do |r|
          # WorldPay is weird... to pay out to a card (visa only on corporate gateway)
          # you must make an authorize request setting the action on the paymentDetails tag to "REFUND"
          #
          # But it's not really a refund so the usual refund method won't work :P
          r.process{authorize(money, payment_method, options.merge(:action => "REFUND"))}
          r.process{capture(money, r.authorization, options.merge(:authorization_validated => true))}
        end
      end

      def test?
        @options[:test] || super  
      end

      private

      def authorize_request(money, payment_method, options)
        commit('authorize', build_authorization_request(money, payment_method, options), "AUTHORISED", options)
      end

      def capture_request(money, authorization, options)
        commit('capture', build_capture_request(money, authorization, options), :ok, options)
      end

      def cancel_request(authorization, options)
        commit('cancel', build_void_request(authorization, options), :ok, options)
      end

      def inquire_request(authorization, options, success_criteria)
        commit('inquiry', build_order_inquiry_request(authorization, options), success_criteria, options)
      end

      def refund_request(money, authorization, options)
        commit('inquiry', build_refund_request(money, authorization, options), :ok, options)
      end

      def build_request
        xml = Builder::XmlMarkup.new :indent => 2
        xml.instruct!
        xml.declare! :DOCTYPE, :paymentService, :PUBLIC, "-//WorldPay//DTD WorldPay PaymentService v1//EN", "http://dtd.wp3.rbsworldpay.com/paymentService_v1.dtd"
        xml.tag! 'paymentService', 'version' => "1.4", 'merchantCode' => @options[:login] do
          yield xml
        end
        xml.target!
      end

      def build_order_modify_request(authorization)
        build_request do |xml|
          xml.tag! 'modify' do
            xml.tag! 'orderModification', 'orderCode' => authorization do
              yield xml
            end
          end
        end
      end

      def build_order_inquiry_request(authorization, options)
        build_request do |xml|
          xml.tag! 'inquiry' do
            xml.tag! 'orderInquiry', 'orderCode' => authorization
          end
        end
      end

      def build_authorization_request(money, payment_method, options)
        build_request do |xml|
          xml.tag! 'submit' do
            xml.tag! 'order', {'orderCode' => options[:order_id], 'installationId' => @options[:inst_id]}.reject{|_,v| !v} do
              xml.description(options[:description].blank? ? "Purchase" : options[:description])
              add_amount(xml, money, options)
              if options[:order_content]
                xml.tag! 'orderContent' do
                  xml.cdata! options[:order_content]
                end
              end
              add_payment_method(xml, money, payment_method, options)
              add_three_d_shopper(xml, options) if options[:three_d]
            end
          end
        end
      end

      def build_capture_request(money, authorization, options)
        build_order_modify_request(authorization) do |xml|
          xml.tag! 'capture' do
            time = Time.now
            xml.tag! 'date', 'dayOfMonth' => time.day, 'month' => time.month, 'year'=> time.year
            add_amount(xml, money, options)
          end
        end
      end

      def build_void_request(authorization, options)
        build_order_modify_request(authorization) do |xml|
          xml.tag! 'cancel'
        end
      end

      def build_refund_request(money, authorization, options)
        build_order_modify_request(authorization) do |xml|
          xml.tag! 'refund' do
            add_amount(xml, money, options)
          end
        end
      end

      def add_amount(xml, money, options)
        xml.tag! 'amount',
          :value => amount(money),
          'currencyCode' => (options[:currency] || currency(money)),
          'exponent' => 2
      end

      def add_payment_method(xml, amount, payment_method, options)
        if payment_method.is_a?(String)
          xml.tag! 'payAsOrder', 'orderCode' => payment_method do
            add_amount(xml, amount, options)
          end
        else
          xml.tag! 'paymentDetails', { 'action' => options[:action] }.reject { |_,v| !v } do
            xml.tag! CARD_CODES[card_brand(payment_method)] do
              xml.tag! 'cardNumber', payment_method.number
              xml.tag! 'expiryDate' do
                xml.tag! 'date', 'month' => format(payment_method.month, :two_digits), 'year' => format(payment_method.year, :four_digits)
              end

              xml.tag! 'cardHolderName', payment_method.name
              xml.tag! 'cvc', payment_method.verification_value

              add_address(xml, 'cardAddress', (options[:billing_address] || options[:address]))
            end

            if options[:three_d]
              add_three_d_session(xml, options)
              add_three_d_secure(xml, options) if options[:three_d][:pa_response]
            end
          end
        end
      end

      def add_three_d_session(xml, options)
        xml.tag! "session",
          "shopperIPAddress" => options[:three_d][:ip_address],
          "id" => options[:three_d][:session_id]
      end

      def add_three_d_shopper(xml, options)
        xml.tag! "shopper" do
          xml.tag! "browser" do
            xml.tag! "acceptHeader", "text/html"
            xml.tag! "userAgentHeader", options[:three_d][:user_agent]
          end
        end

        if options[:three_d][:echo_data]
          xml.tag! "echoData", options[:three_d][:echo_data]
        end
      end

      def add_three_d_secure(xml, options)
        xml.tag! "info3DSecure" do
          xml.tag! "paResponse", options[:three_d][:pa_response]
        end
      end

      def add_address(xml, element, address)
        return if address.nil?

        xml.tag! element do
          xml.tag! 'address' do
            xml.tag! 'firstName',       address[:first_name]       if address[:first_name]
            xml.tag! 'lastName',        address[:last_name]        if address[:last_name]
            xml.tag! 'address1',        address[:address_1]        if address[:address_1]
            xml.tag! 'address2',        address[:address_2]        if address[:address_2]
            xml.tag! 'postalCode',      address[:postal_code]      if address[:postal_code]
            xml.tag! 'city',            address[:city]             if address[:city]
            xml.tag! 'state',           address[:state]            if address[:state]
            xml.tag! 'countryCode',     address[:country_code]     if address[:country_code]
            xml.tag! 'telephoneNumber', address[:telephone_number] if address[:telephone_number]
          end
        end
      end

      def parse(action, xml)
        parse_element({:action => action}, REXML::Document.new(xml))
      end

      def parse_element(raw, node)
        node.attributes.each do |k, v|
          raw["#{node.name.underscore}_#{k.underscore}".to_sym] = v
        end
        if node.has_elements?
          raw[node.name.underscore.to_sym] = true unless node.name.blank?
          node.elements.each{|e| parse_element(raw, e) }
        else
          raw[node.name.underscore.to_sym] = node.text unless node.text.nil?
        end
        raw
      end

      def commit(action, request, success_criteria, options = {})
        headers = {
          'Content-Type'  => 'text/xml',
          'Authorization' => encoded_credentials
        }

        if options[:three_d] && options[:three_d][:cookie]
          headers['Cookie'] = options[:three_d][:cookie]
        end

        xmr = ssl_post((test? ? self.test_url : self.live_url), request, headers)

        raw = parse(action, xmr)

        Response.new(
          success_from(raw, success_criteria),
          message_from(raw),
          raw,
          :authorization => authorization_from(raw),
          :test => test?,
          :headers => xmr.headers)
      rescue ActiveMerchant::ResponseError => e
        if e.response.code.to_s == "401"
          return Response.new(false, "Invalid credentials", {}, :test => test?)
        else
          raise e
        end
      end

      def success_from(raw, success_criteria)
        (raw[:last_event] == success_criteria ||
          raw[:ok].present?)
      end

      def message_from(raw)
        (raw[:iso8583_return_code_description] ||
          raw[:error] ||
          "SUCCESS")
      end

      def authorization_from(raw)
        pair = raw.detect{|k,v| k.to_s =~ /_order_code$/}
        (pair ? pair.last : nil)
      end

      def encoded_credentials
        credentials = "#{@options[:login]}:#{@options[:password]}"
        "Basic #{[credentials].pack('m').strip}"
      end
    end
  end

  # 3D Monkey Patches
  class WorldPayResponse < String
    def initialize(resp)
      @resp = resp
      super(resp.body)
    end

    def headers
      _headers = {}
      @resp.each_header { |k,v| _headers[k] = v }
      _headers
    end
  end

  module PostsData
    private
    def handle_response(response)
      case response.code.to_i
      when 200...300
        WorldPayResponse.new(response)
      else
        raise ResponseError.new(response)
      end
    end
  end
end

