package com.example.securityprojet.service.impl;

import com.example.securityprojet.bean.Role;
import com.example.securityprojet.bean.User;
import com.example.securityprojet.dao.UserDao;
import com.example.securityprojet.service.facade.RoleService;
import com.example.securityprojet.service.facade.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private RoleService roleService;


    @Lazy
    PasswordEncoder passwordEncoder;

    @Override
    public List<User> findAll() {
        return userDao.findAll();
    }

    @Override
    public User findByUsername(String username) {
        if (username == null)
            return null;
        return userDao.findByUsername(username);
    }

    @Override
    public User findByUsernameWithRoles(String username) {
        if (username == null)
            return null;
        return userDao.findByUsername(username);
    }

    @Override
    @Transactional
    public int deleteByUsername(String username) {
        return userDao.deleteByUsername(username);
    }

    @Override
    public User findById(Long id) {
        if (id == null)
            return null;
        return userDao.getOne(id);
    }

    @Transactional
    public void deleteById(Long id) {
        userDao.deleteById(id);
    }

    @Override
    public User save(User user) {
        User foundedUserByUsername = findByUsername(user.getUsername());
        User foundedUserByEmail = userDao.findByEmail(user.getEmail());
        if (foundedUserByUsername != null || foundedUserByEmail != null) {
            return null;
        } else {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setAccountNonExpired(true);
            user.setAccountNonLocked(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setPasswordChanged(false);

            // Assurez-vous de ne pas sauvegarder les rôles en double
            if (user.getRoles() != null) {
                Collection<Role> roles = new ArrayList<>();
                for (Role role : user.getRoles()) {
                    roles.add(roleService.save(role));
                }
                user.setRoles(roles);
            }

            User mySaved = userDao.save(user);
            return mySaved;
        }
    }

    @Override
    public User update(User user) {
        User foundedUser = findById(user.getId());
        if (foundedUser == null) {
            return null;
        } else {
            // Mise à jour des attributs utilisateur
            foundedUser.setBio(user.getBio());
            foundedUser.setEmail(user.getEmail());
            foundedUser.setUsername(user.getUsername());
            foundedUser.setPrenom(user.getPrenom());
            foundedUser.setNom(user.getNom());

            // Mise à jour des rôles
            foundedUser.setRoles(new ArrayList<>());
            if (user.getRoles() != null) {
                Collection<Role> roles = new ArrayList<>();
                for (Role role : user.getRoles()) {
                    roles.add(roleService.save(role));
                }
                foundedUser.setRoles(roles);
            }

            return userDao.save(foundedUser);
        }
    }

    @Override
    @Transactional
    public int delete(Long id) {
        User foundedUser = findById(id);
        if (foundedUser == null) {
            return -1;
        }
        userDao.delete(foundedUser);
        return 1;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return findByUsernameWithRoles(username);
    }
}
