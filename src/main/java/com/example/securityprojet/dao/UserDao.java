package com.example.securityprojet.dao;

import com.example.securityprojet.bean.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserDao  extends JpaRepository<User, Long> {
    User findByUsername(String username);
    int deleteByUsername(String username);
    User findByEmail(String email);
    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
