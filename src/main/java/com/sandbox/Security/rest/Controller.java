package com.sandbox.Security.rest;

import com.sandbox.Security.service.Service;
import com.sandbox.Security.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class Controller {

    private final Service service;
    private final TokenService tokenService;

    @GetMapping("/users")
    public ResponseEntity<Object> findAllUsers(){
        return ResponseEntity.ok(service.findAll());
    }

    @PostMapping("/token")
    public ResponseEntity<Object> getToken(Authentication authentication){
        String token = tokenService.generatetoken(authentication);
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

    @PostMapping("/post")
    public String post(){
        return "uspesno";
    }

    //https://www.youtube.com/watch?v=cEGmXj79iRs&list=PLbuI9mmWSoUFP8NhYN_AQeSHh1KFEkGev&index=2

}
