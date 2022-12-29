package com.example.cognito.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class UserDetail  {
    private String firstName;
    private String lastName;
    private String email;
}
