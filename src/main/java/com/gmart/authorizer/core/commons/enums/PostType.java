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

public enum PostType {
	VIDEO("PP"), TEXT(""), IMAGE(""), LINK("CP");

	private String type;

	public String getType() {
		return this.type;
	}

	private PostType(String type) {
		this.type = type;
	}
}
