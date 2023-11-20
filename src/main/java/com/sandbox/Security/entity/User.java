package com.sandbox.Security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private long id;
    private boolean active = true;
    private String username;
    private String password;
    @ManyToOne(optional = false)
    @JoinColumn(name = "roleid")
    private Role role;

}
