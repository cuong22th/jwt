package com.example.jwt.service;

import com.example.jwt.entity.ERole;
import com.example.jwt.entity.Roles;
import com.example.jwt.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RoleServiceImp implements RoleService{
    @Autowired
    private RoleRepository roleRepository;
    @Override
    public Optional<Roles> findByRoleName(ERole roleName) {

        return roleRepository.findByRoleName(roleName);
    }
}
