/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.api;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolationException;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gmart.authorizer.core.commons.dtos.requests.SignUpRequest;
import com.gmart.authorizer.core.commons.dtos.responses.CustomError;
import com.gmart.authorizer.core.commons.dtos.responses.SignUpResponse;
import com.gmart.authorizer.core.commons.enums.PermissionName;
import com.gmart.authorizer.core.commons.enums.RoleName;
import com.gmart.authorizer.core.commons.enums.SignUpStatus;
import com.gmart.authorizer.core.domain.Permission;
import com.gmart.authorizer.core.domain.Role;
import com.gmart.authorizer.core.domain.UserInfo;
import com.gmart.authorizer.core.exception.UserSignUpException;
import com.gmart.authorizer.core.service.UserCoreService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 29 mars 2021
 **/
@RestController
@RequestMapping("/users")
@Slf4j
public class UserAccountController {

	// DI of User account service
	@Autowired
	private UserCoreService userCoreService;

	// DI of PasswordEncoder
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;

	@PostMapping("/signup")
	public ResponseEntity<SignUpResponse> signup(@Valid @RequestBody SignUpRequest newUser, HttpServletRequest request,
			HttpServletResponse response) {
		try {
			log.info(newUser.toString());

			// Successful sign up request
			UserInfo userTobeRegistred = new UserInfo();
			userTobeRegistred.setPassword(passwordEncoder.encode(newUser.getPassword()));
			userTobeRegistred.setUsername(newUser.getUsername());
			userTobeRegistred.setEmail(newUser.getEmail());

			// To be modified, just for test issue
			Set<Role> roles = new HashSet<>();
			Role userRole = new Role();
			Role adminRole = new Role();

			userRole.setRoleName(RoleName.STANDARD_USER.getName());
			Permission readPermission = new Permission();
			readPermission.setPermissionName(PermissionName.CAN_READ_USER.getName());

			userRole.setPermissions(new HashSet<>(Arrays.asList(readPermission)));

			adminRole.setRoleName(RoleName.ADMIN_USER.getName());
			Permission canCreateUserPermission = new Permission();
			canCreateUserPermission.setPermissionName(PermissionName.CAN_CREATE_USER.getName());

			adminRole.setPermissions(new HashSet<>(Arrays.asList(canCreateUserPermission)));

			roles.add(userRole);
			roles.add(adminRole);

			userTobeRegistred.setRoles(roles);

			// Storing the object into database
			userCoreService.save(userTobeRegistred);

			// Creating the SignUp response
			SignUpResponse signUpResponse = new SignUpResponse();
			signUpResponse.setSignUpStatus(SignUpStatus.CREATED);
			// Returning after Appending the response to the body of the HttpResponse
			return ResponseEntity.accepted().body(signUpResponse);

		} catch (Exception e) {
			log.error(e.getClass().getName() + " | Message " + e.getMessage());
			SignUpResponse signUpResponse = new SignUpResponse();
			signUpResponse.setSignUpStatus(SignUpStatus.NOT_CREATED);
			CustomError error = new CustomError();
			if (e instanceof UserSignUpException) {
				error.setCode(((UserSignUpException) e).getCode());
				error.setMessage(e.getMessage());

			}
			if (e instanceof ConstraintViolationException || e instanceof DataIntegrityViolationException
					|| e instanceof Exception) {
				error.setCode("409");
				error.setMessage("This user : '" + newUser.getUsername() + "' has been already registred!");
			}

			signUpResponse.setError(error);
			return ResponseEntity.status(Integer.parseInt(error.getCode())).body(signUpResponse);

		}
	}
}
