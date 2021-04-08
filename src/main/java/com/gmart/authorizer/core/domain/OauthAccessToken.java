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
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.GenericGenerator;

import lombok.Data;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 30 mars 2021
 **/
@Entity
@Table(name = "OAUTH_ACCESS_TOKEN")
@Data
public class OauthAccessToken {
	@Id
	@GeneratedValue(generator = "uuid")
	@GenericGenerator(name = "uuid", strategy = "uuid2")
	@Column(name="AUTHENTICATIONID")
	private String authenticationID;

	@Column(name="TOKEN")
	private String token;

	@Column(name="TOKENID")
	private String tokenID;

	@Column(name = "TOKENBLOB")
	private String tokenBlob;

	@Column(name = "USER_NAME")
	private String userName;

	@Column(name = "AUTHENTICATION")
	private String authentication;

	@Column(name = "REFRESHTOKEN")
	private String refreshToken;

	@Column(name = "CLIENTID")
	private String clientID;
}
