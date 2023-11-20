package com.sandbox.Security.service;

import com.sandbox.Security.entity.User;
import com.sandbox.Security.repository.Repository;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@org.springframework.stereotype.Service
@Transactional
@RequiredArgsConstructor
public class Service {

    private final Repository repository;

    public List<User> findAll(){
        return repository.findAll();
    }

}
