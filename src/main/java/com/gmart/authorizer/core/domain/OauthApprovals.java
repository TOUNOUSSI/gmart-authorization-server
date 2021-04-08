/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.domain;


import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

import lombok.Data;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 6 avr. 2021
 **/
@Data
@Table(name = "OAUTH_APPROVALS")
@Entity
public class OauthApprovals {
	@Id
	@Column(name = "USERID")
	private String userId;

	@Column(name = "CLIENTId")
	private String clientId;

	@Column(name = "SCOPE")
	private String scope;

	@Column(name = "STATUS")
	private String status;

    @Temporal(TemporalType.TIMESTAMP)
	@Column(name = "EXPIRESAT")
	private Date expiresAt;

    @Temporal(TemporalType.TIMESTAMP)
	@Column(name = "LASTMODIFIEDAT")
	private Date lastModifiedAt;
}
