package com.dailycodework.ilibrary.security.jwt;

import lombok.Data;

@Data
public class JwtAuthenticationRequest
{
    // create a request
    private String userName;
    private String password;

}
