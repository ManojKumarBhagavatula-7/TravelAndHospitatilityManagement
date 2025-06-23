package com.cts.booking.config;

import java.util.Optional;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Import;
import org.springframework.data.domain.AuditorAware;

@TestConfiguration
public class NoJpaAuditingConfig {
    @Bean
    AuditorAware<String> auditorProvider() {
        return () -> Optional.of("test-user");
    }
}
