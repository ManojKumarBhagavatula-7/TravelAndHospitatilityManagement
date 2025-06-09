package com.cts.travelpackage.config;

import java.util.Optional;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@Configuration
@EnableJpaAuditing
public class JpaAuditingConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> Optional.of("system"); // Replace with actual user logic
        
        //while using spring security replce the above code with the below code
//        return () -> Optional.ofNullable(
//        	    SecurityContextHolder.getContext().getAuthentication().getName()
//        	);

    }
}
