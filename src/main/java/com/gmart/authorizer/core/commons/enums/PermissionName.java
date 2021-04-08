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

public enum PermissionName {
	CAN_CREATE_USER("can_create_user"), CAN_UPDATE_USER("can_update_user"), CAN_READ_USER("can_read_user"),
	CAN_DELETE_USER("can_delete_user");

	private String name;

	private PermissionName(String name) {
		this.name = name;
	}

	public String getName() {
		return this.name;
	}
}
