/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.api;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gmart.authorizer.core.commons.dtos.requests.SignInRequest;
import com.gmart.authorizer.core.domain.UserInfo;
import com.gmart.authorizer.core.exception.UserSignInException;
import com.gmart.authorizer.core.provider.JwtTokenProvider;
import com.gmart.authorizer.core.service.UserCoreService;

import lombok.extern.slf4j.Slf4j;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 29 mars 2021
 **/
@Slf4j
@RestController
@RequestMapping("/token")
public class AuthorizationController {
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private UserCoreService userCoreService;

	@Autowired
	private JwtTokenProvider jwtProvider;

	/**
	 * Get User-id from Token
	 *
	 * @param token
	 * @return Long
	 */
	@PostMapping("/extract-details")
	public String extractDetailsFromToken(@RequestBody String token) {
		return jwtProvider.getUsernameFromJWT(token);
	}

	/**
	 * Validate authentication Token
	 *
	 * @param authToken
	 * @return Boolean
	 */
	@PostMapping("/validate")
	public boolean validateToken(@RequestBody String authToken) {
		return jwtProvider.validateToken(authToken);
	}

	/**
	 * Generate new authentication Token based on Spring security Authentication
	 *
	 * @param authentication
	 * @return String
	 */
	@PostMapping("/generate-token")
	public ResponseEntity<String> signIn(@Valid @RequestBody SignInRequest loginRequest, HttpServletRequest request,
			HttpServletResponse response) {
		String jwt = "";
		log.info("Authentication process started for the request : " + loginRequest.toString());
		try {

			UserInfo userCore = userCoreService.loadUserByUsername(loginRequest.getUsername());
			if (userCore != null) {
				log.info("User has been authenticated successfully ");
				log.info(loginRequest.toString());
				Authentication authentication = authenticationManager
						.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
								loginRequest.getPassword(), userCore.getAuthorities()));
				request.setAttribute("authentication", authentication);
				jwt = jwtProvider.generateToken(authentication);

			} else {
				throw new UserSignInException("Incorrect username or password!", "404");
			}

			return ResponseEntity.status(HttpStatus.OK).body(jwt);

		} catch (UserSignInException e) {
			log.error(e.getMessage());
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);

		} catch (Exception e) {
			log.error(e.getMessage());
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
		}
	}

	@GetMapping(value = "/health")
	public ResponseEntity<String> health() {
		return new ResponseEntity<>("Hello", HttpStatus.OK);
	}

}
