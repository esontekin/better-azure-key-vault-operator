package com.akvoperator;

import com.akvoperator.common.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication(exclude = {OAuth2ClientAutoConfiguration.class})
@EnableConfigurationProperties(AppProperties.class)
public class AkvOperatorApplication {

    public static void main(String[] args) {
        SpringApplication.run(AkvOperatorApplication.class, args);
    }
}
