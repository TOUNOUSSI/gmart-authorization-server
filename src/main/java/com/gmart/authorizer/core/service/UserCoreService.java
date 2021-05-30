/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

import com.gmart.authorizer.core.domain.UserInfo;
import com.gmart.authorizer.core.repository.UserCoreRepository;

import lombok.Data;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 2 avr. 2021
 **/
@Data
@Service
public class UserCoreService implements UserDetailsService {
	@Autowired
	private UserCoreRepository userRepository;

	public UserInfo loadUserById(String id) {
		return this.userRepository.getOne(id);
	}

	public List<UserInfo> getAllUsers() {
		return this.userRepository.findAll();
	}

	public List<UserInfo> getMatchingUsersList(String criteria) {
		return this.userRepository.findByUsernameContainingIgnoreCase(criteria);
	}

	@Override
	public UserInfo loadUserByUsername(String username) {
		UserInfo userInfo = userRepository.findByUsername(username);
		if (userInfo == null) {
			throw new BadCredentialsException("Bad Credentials");
		}

		new AccountStatusUserDetailsChecker().check(userInfo);

		return userInfo;
	}

	public UserInfo findByUsername(String username) {
		return userRepository.findByUsername(username);
	}

	public UserInfo save(UserInfo user) {
		return userRepository.saveAndFlush(user);
	}

	public UserInfo update(UserInfo user) {
		return userRepository.save(user);
	}

}
