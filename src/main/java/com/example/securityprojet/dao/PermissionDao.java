package com.example.securityprojet.dao;

import com.example.securityprojet.bean.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionDao extends JpaRepository<Permission, Long> {
    public Permission findByName(String name);
}
