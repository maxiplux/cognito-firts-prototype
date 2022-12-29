package com.example.cognito.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class UserSignInRequest {
    private String username;
    private String email;
    private String password;
    private String newPassword;
}
