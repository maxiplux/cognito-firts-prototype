package com.example.cognito.config.aws;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class AwsCognitoConfig {
    private  String clientId;
    private  String  userPoolId;
    private  String  region;
    private  String connectionTimeout;
    private  String readTimeout;
    private  String jwk;

}
