package com.learning.gateway;

import com.learning.gateway.filter.ValidateBasicAuthFilter;
import com.learning.gateway.filter.ValidateOAuthFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class GatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(GatewayApplication.class, args);
	}

	@Autowired
	private ValidateOAuthFilter validateOAuthFilter;

	@Autowired
	private ValidateBasicAuthFilter validateBasicAuthFilter;

	@Bean
	public RouteLocator myRoutes(RouteLocatorBuilder builder){
		return builder.routes()
				.route( r -> r.path("/user/password/reset")
						.filters(f-> f.filter(validateBasicAuthFilter))
						.uri("http://localhost:8081/user"))
				.route( r -> r.path("/user/**")
						.filters(f-> f.filter(validateOAuthFilter))
						.uri("http://localhost:8081/user"))
				.route( r -> r.path("/auth/oauth/token","/auth/oauth/token/revoke")
						.uri("http://localhost:8083/auth"))
				.build();
	}

}
