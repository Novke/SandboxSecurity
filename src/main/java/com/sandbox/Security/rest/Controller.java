package com.sandbox.Security.rest;

import com.sandbox.Security.service.UserService;
import com.sandbox.Security.service.TokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class Controller {

    private final UserService userService;
    private final TokenService tokenService;

    @GetMapping("/users")
    public ResponseEntity<Object> findAllUsers(){
        return ResponseEntity.ok(userService.findAll());
    }

    @PostMapping("/token")
    public ResponseEntity<Object> getToken(Authentication authentication){

        log.debug("Token request for user: '{}'", authentication.getName()); //**PLACEHOLDER

        String token = tokenService.generateToken(authentication);
        log.debug("Token: {}", token);

        return ResponseEntity.ok(token);
    }

    @GetMapping("/admin")
    public ResponseEntity<Object> findAllAdmins(){
        return ResponseEntity.ok("admin");
    }

    @GetMapping("/all")
    public String getAll(){
        return "uspesno";
    }

    @GetMapping("/norole")
    public String getNoRole(Authentication authentication){
        System.err.println("===================");
        log.debug("Token request for user: '{}'", authentication.getName());
        System.err.println("===================");
        return "uspesno";
    }

    @PostMapping("/post")
    public String post(){
        return "uspesno";
    }

    //https://www.youtube.com/watch?v=cEGmXj79iRs&list=PLbuI9mmWSoUFP8NhYN_AQeSHh1KFEkGev&index=2

}
