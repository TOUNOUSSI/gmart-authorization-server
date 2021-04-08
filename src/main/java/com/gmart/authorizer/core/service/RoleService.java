/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.service;

import org.springframework.beans.factory.annotation.Autowired;

import com.gmart.authorizer.core.domain.Role;
import com.gmart.authorizer.core.repository.RoleRepository;

import lombok.Data;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 5 avr. 2021
 **/
@Data
public class RoleService {
	@Autowired
	private RoleRepository repository;

	public Role saveContent(Role role) {
		return repository.save(role);
	}
}
