package com.dailycodework.ilibrary.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/authenticate")
public class JwtController
{
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    @PostMapping
    // this controller validate the user whether authenticated and genreate token
     public String getTokenForAuthenticatedUser(@RequestBody JwtAuthenticationRequest authRequest)
     {
       // Authenticate the user and authentication manager will to librarysecurityconfig class
         Authentication authentication=authenticationManager
                 .authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUserName(),
                         authRequest.getPassword()));
         if(authentication.isAuthenticated())
         {
             return jwtService.getGeneratedToken(authRequest.getUserName());
         }
         else
         {
             throw new UsernameNotFoundException("Invalid User Credentials");
         }
     }
}
