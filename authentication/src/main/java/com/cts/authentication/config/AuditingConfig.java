package com.cts.authentication.config;

import com.cts.authentication.CustomUserDetails;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class AuditingConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated()) {
                // Return "anonymous" or a default user if not authenticated
                return Optional.of("anonymous");
            }
            // Assuming the principal is an instance of CustomUserDetails
            if (authentication.getPrincipal() instanceof CustomUserDetails) {
                return Optional.of(((CustomUserDetails) authentication.getPrincipal()).getUsername());
            }
            // For other types of principals (e.g., anonymous, remember-me), return the name
            return Optional.of(authentication.getName());
        };
    }
}