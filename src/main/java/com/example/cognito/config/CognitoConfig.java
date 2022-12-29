package com.example.cognito.config;

import com.example.cognito.config.aws.AwsConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;

@Configuration
public class CognitoConfig {



    @Autowired
    private AwsConfig awsConfig;

    @Bean
    public AWSCognitoIdentityProvider cognitoClient() {


        BasicAWSCredentials awsCreds = new BasicAWSCredentials(awsConfig.getAccess().getKey(), awsConfig.getAccess().getSecret());

        return AWSCognitoIdentityProviderClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCreds)).withRegion(awsConfig.getAccess().getRegion())
                .build();
    }
}

