package com.example.jwt.service;

import com.example.jwt.entity.ERole;
import com.example.jwt.entity.Roles;

import java.util.Optional;

public interface RoleService {
    Optional<Roles> findByRoleName(ERole roleName);
}
