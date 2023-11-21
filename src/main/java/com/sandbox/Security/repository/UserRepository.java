package com.sandbox.Security.repository;

import com.sandbox.Security.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

@org.springframework.stereotype.Repository
public interface UserRepository extends JpaRepository<User, Long> {
}
