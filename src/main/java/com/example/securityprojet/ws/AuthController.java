package com.example.securityprojet.ws;


import com.example.securityprojet.bean.Role;
import com.example.securityprojet.bean.User;
import com.example.securityprojet.common.SecurityParams;
import com.example.securityprojet.dao.RoleDao;
import com.example.securityprojet.dao.UserDao;
import com.example.securityprojet.jwt.JwtUtils;
import com.example.securityprojet.payload.request.LoginRequest;
import com.example.securityprojet.payload.request.SignupRequest;
import com.example.securityprojet.payload.response.JwtResponse;
import com.example.securityprojet.payload.response.MessageResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

//@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserDao userRepository;

    @Autowired
    RoleDao roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        User userDetails = (User) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        HttpHeaders headers = new HttpHeaders();
        headers.add(SecurityParams.JWT_HEADER_NAME,SecurityParams.HEADER_PREFIX+jwt);
        return ResponseEntity.ok()
                .headers(headers)
                .body(new JwtResponse(jwt,
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        roles));
    }


    @PostMapping("signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }
}