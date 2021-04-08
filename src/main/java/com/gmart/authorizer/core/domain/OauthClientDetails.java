/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.domain;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 4 avr. 2021
 **/
@Data
@Entity
@Table(name = "OAUTH_CLIENT_DETAILS")
public class OauthClientDetails {
	@Id
	@Column(name = "CLIENT_ID")
	private String clientId;

	@Column(name = "CLIENT_SECRET")
	private String clientSecret;

	@Column(name = "SCOPE")
	private String scope;

	@Column(name = "AUTHORIZED_GRANT_TYPES")
	private String authorizedGrantTypes;

	@Column(name = "WEB_SERVER_REDIRECT_URI")
	private String webServerRedirectUri;

	@Column(name = "AUTHORITIES")
	private String authorities;

	@Column(name = "ACCESS_TOKEN_VALIDITY")
	private Integer accessTokenValidity;

	@Column(name = "REFRESH_TOKEN_VALIDITY")
	private Integer refreshTokenValidity;

	@Column(name = "AUTOAPPROVE")
	private String autoApprove;

	@Column(name = "RESOURCE_IDS")
	 private String resourceIDS;

	@Column(name="ADDITIONAL_INFORMATION")
	private String additionalInformation;

}
