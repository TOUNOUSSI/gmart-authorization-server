/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */

package com.gmart.authorizer.core.commons.enums;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 16 nov. 2020
 **/

public enum RoleName {

	ADMIN_USER("role_admin"), STANDARD_USER("role_user"), MANAGER_USER("role_manager");

	private String name;

	private RoleName(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}
}
