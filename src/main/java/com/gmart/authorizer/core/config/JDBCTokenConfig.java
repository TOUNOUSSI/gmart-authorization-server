/*
 *  This work is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/3.0/deed.en_US">Creative Commons Attribution 3.0 Unported License</a>.
 *  Copyright © GMART, unpublished work. This computer program
 *  includes confidential, proprietary information and is a trade secret of GMART Inc.
 *  All use, disclosure, or reproduction is prohibited unless authorized
 *  in writing by TOUNOUSSI Youssef. All Rights Reserved.
 */
package com.gmart.authorizer.core.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * @author <a href="mailto:youssef.tounoussi@gmail.com">TOUNOUSSI Youssef</a>
 * @create 3 avr. 2021
 **/

@Configuration
public class JDBCTokenConfig {

	@Value("${spring.datasource.url}")
	private String datasourceUrl;

	@Value("${spring.datasource.driver-class-name}")
	private String dbDriverClassName;

	@Value("${spring.datasource.username}")
	private String dbUsername;

	@Value("${spring.datasource.password}")
	private String dbPassword;

	@Bean
	public DataSource dataSource() {
		final DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(dbDriverClassName);
		dataSource.setUrl(datasourceUrl);
		dataSource.setUsername(dbUsername);
		dataSource.setPassword(dbPassword);
		return dataSource;
	}
}
