package com.gmart.authorizer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@EnableAutoConfiguration
@EnableEurekaClient
@SpringBootApplication
public class GmartResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(GmartResourceServerApplication.class, args);
	}

}
