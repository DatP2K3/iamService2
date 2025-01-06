package com.evotek.iam.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.CommonsRequestLoggingFilter;

@Configuration
public class LoggingConfig {
    @Bean
    public CommonsRequestLoggingFilter requestLoggingFilter() {
        CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
        loggingFilter.setIncludeClientInfo(true); // Log thông tin client (IP, Session ID)
        loggingFilter.setIncludeQueryString(true); // Log query string
        loggingFilter.setIncludeHeaders(false); // Không log headers (để tránh log thông tin nhạy cảm)
        loggingFilter.setIncludePayload(true); // Log payload của request
        loggingFilter.setMaxPayloadLength(10000); // Giới hạn độ dài payload
        return loggingFilter;
    }
}
