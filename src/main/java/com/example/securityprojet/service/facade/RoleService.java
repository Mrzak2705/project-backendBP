package com.example.securityprojet.service.facade;


import com.example.securityprojet.bean.Role;

import java.util.List;

public interface RoleService {
    List<Role> findAll();

    Role findByAuthority(String authority);

    Role findById(Long id);

    void deleteById(Long id);

    Role save(Role role);

    List<Role> create(List<Role> roles);

    public Role update(Role role);

    int delete(Role role);

    int deleteByAuthority(String authority);

    List<Role> findByUserName(String username);
}
