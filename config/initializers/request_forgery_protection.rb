module ActionController
  module RequestForgeryProtection
    private

    def valid_authenticity_token?(session, encoded_masked_token)
      if encoded_masked_token.nil? || encoded_masked_token.empty? || !encoded_masked_token.is_a?(String)
        return false
      end

      begin
        masked_token = Base64.strict_decode64(encoded_masked_token)
      rescue ArgumentError # encoded_masked_token is invalid Base64
        return false
      end

      # See if it's actually a masked token or not. In order to
      # deploy this code, we should be able to handle any unmasked
      # tokens that we've issued without error.

      if masked_token.length == AUTHENTICITY_TOKEN_LENGTH
        # This is actually an unmasked token. This is expected if
        # you have just upgraded to masked tokens, but should stop
        # happening shortly after installing this gem
        compare_with_real_token masked_token, session

      elsif masked_token.length == AUTHENTICITY_TOKEN_LENGTH * 2
        csrf_token = unmask_token(masked_token)

        # For easy debugging, consider using pry or else.
        puts "per_form_csrf_tokens: #{per_form_csrf_tokens}"
        puts "compare_with_real_token: #{compare_with_real_token(csrf_token, session)}"
        puts "valid_per_form_csrf_token?: #{valid_per_form_csrf_token?(csrf_token, session)}"

        compare_with_real_token(csrf_token, session) ||
          valid_per_form_csrf_token?(csrf_token, session)
      else
        false # Token is malformed
      end
    end
  end
end
