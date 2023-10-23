package com.example.jwt.service;

import com.example.jwt.entity.Users;


public interface UserService {
    Users findByUserName(String userName);
    boolean existsByUserName(String userName);

    boolean existsByEmail(String  email);

    Users saveOrUpdate(Users user);
}
