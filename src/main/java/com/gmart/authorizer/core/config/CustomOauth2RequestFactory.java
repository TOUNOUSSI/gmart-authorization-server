/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.config;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 5 avr. 2021
 **/

public class CustomOauth2RequestFactory extends DefaultOAuth2RequestFactory {

	@Autowired
	private TokenStore tokenStore;

	@Autowired
	private UserDetailsService userDetailsService;

	public CustomOauth2RequestFactory(ClientDetailsService clientDetailsService) {
		super(clientDetailsService);
	}


	@Override
	public TokenRequest createTokenRequest(Map<String, String> requestParameters,
			ClientDetails authenticatedClient) {
		if (requestParameters.get("grant_type").equals("refresh_token")) {
			OAuth2Authentication authentication = tokenStore.readAuthenticationForRefreshToken(
					tokenStore.readRefreshToken(requestParameters.get("refresh_token")));
			SecurityContextHolder.getContext()
					.setAuthentication(new UsernamePasswordAuthenticationToken(authentication.getName(), null,
							userDetailsService.loadUserByUsername(authentication.getName()).getAuthorities()));
		}
		return super.createTokenRequest(requestParameters, authenticatedClient);
	}
}