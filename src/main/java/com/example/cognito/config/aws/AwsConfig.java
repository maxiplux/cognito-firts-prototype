package com.example.cognito.config.aws;

import com.example.cognito.config.aws.AwsAccess;
import com.example.cognito.config.aws.AwsCognitoConfig;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
@Configuration
@ConfigurationProperties(prefix = "aws")
@AllArgsConstructor
@Data
@NoArgsConstructor
public class AwsConfig {
    private AwsCognitoConfig cognito;
    private AwsAccess access;
}
