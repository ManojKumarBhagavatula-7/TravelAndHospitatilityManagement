package com.cts.travelpackage.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	 
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    http
	        .authorizeHttpRequests(authorize -> authorize
	            .requestMatchers("/h2-console/**").permitAll()
	            .anyRequest().authenticated()
	        )
	        .csrf(csrf -> csrf
	            .ignoringRequestMatchers("/h2-console/**")
	        )
	        .headers(headers -> headers
	            .frameOptions().sameOrigin()
	        );
	return http.build();
	}
}
