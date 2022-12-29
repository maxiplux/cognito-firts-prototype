package com.example.cognito.config.aws;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class AwsAccess {
    private  String key;
    private  String secret;
    private  String region;


}
