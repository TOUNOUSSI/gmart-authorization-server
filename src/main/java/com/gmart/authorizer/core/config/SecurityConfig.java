/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.gmart.authorizer.core.filter.JwtAuthenticationFilter;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 3 avr. 2021
 **/
@EnableWebSecurity
@Order(SecurityProperties.BASIC_AUTH_ORDER)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsService userDetailsService;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean(name = "authenticationManagerBean")
	public AuthenticationManager getAuthenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/webjars/**", "/resources/**");

	}

	@Override
	public void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable().exceptionHandling()
//				.authenticationEntryPoint(
//						(request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED))
//				.and().authorizeRequests().antMatchers("/**").authenticated().and().httpBasic();
		//http.httpBasic().disable();

		http.authorizeRequests()
				.antMatchers("/", "/*.js", "/*.jsp", "/favicon.ico", "/**/*.png", "/**/*.gif", "/**/*.svg", "/**/*.jpg",
						"/**/*.html", "/**/*.css", "/**/*.js", "/authentication/**", "/invalidSession",
						"/resources/invalidSession")
				.permitAll().antMatchers("/h2-console/**", "/h2-console").permitAll()
				.antMatchers("/login", "/logout.do", "/oauth/*","/token/generate-token","/users/signup").permitAll()
				.antMatchers("/**").authenticated()
				.and().httpBasic();
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Bean
	public JwtAuthenticationFilter authenticationTokenFilterBean() throws Exception {
		return new JwtAuthenticationFilter();
	}

}
