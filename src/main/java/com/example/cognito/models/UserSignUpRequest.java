package com.example.cognito.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class UserSignUpRequest {
    private String username;
    private String email;
    private String password;
}
