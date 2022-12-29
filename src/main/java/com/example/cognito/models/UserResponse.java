package com.example.cognito.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@AllArgsConstructor
@Data
@NoArgsConstructor
public class UserResponse {
    private Date creationDate;
    private String username;
    private String userStatus;
    private Date lastModifiedDate;


}
