package com.cts.booking.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
@Import(NoJpaAuditingConfig.class)
@TestConfiguration
public class TestSecurityConfig {
    @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    	http
    	.csrf(csrf -> csrf.disable())
    	.authorizeHttpRequests(auth -> auth
		.anyRequest().permitAll());
    	return http.build();

    }
}

