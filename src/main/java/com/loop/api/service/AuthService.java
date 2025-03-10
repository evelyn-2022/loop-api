package com.loop.api.service;

import com.loop.api.dto.RegisterRequest;
import com.loop.api.dto.LoginRequest;
import com.loop.api.dto.LoginResponse;
import com.loop.api.exception.InvalidCredentialsException;
import com.loop.api.exception.UserAlreadyExistsException;
import com.loop.api.model.User;
import com.loop.api.repository.UserRepository;
import com.loop.api.security.JwtTokenProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public String registerUser(RegisterRequest request) {
        if (request.getEmail() == null || request.getEmail().isBlank() ||
                request.getUsername() == null || request.getUsername().isBlank() ||
                request.getPassword() == null || request.getPassword().isBlank()) {
            throw new IllegalArgumentException("Email, username, and password cannot be empty or null");
        }

        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("User with email " + request.getEmail() + " already exists");
        }

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new UserAlreadyExistsException("User with username " + request.getUsername() + " already exists");
        }

        try {
            User user = new User();
            user.setEmail(request.getEmail());
            user.setUsername(request.getUsername());
            user.setPassword(passwordEncoder.encode(request.getPassword()));

            userRepository.save(user);
            return "User registered successfully";
        } catch (Exception e) {
            throw new RuntimeException("Error registering user: " + e.getMessage());
        }
    }

    public LoginResponse loginUser(LoginRequest request) {
        if (request.getEmail() == null || request.getPassword() == null) {
            throw new IllegalArgumentException("Email and password cannot be null");
        }

        try {
            Optional<User> userOptional = userRepository.findByEmail(request.getEmail());

            if (userOptional.isEmpty() || !passwordEncoder.matches(request.getPassword(), userOptional.get().getPassword())) {
                throw new InvalidCredentialsException("Invalid email or password");
            }

            String token = jwtTokenProvider.generateToken(request.getEmail());
            return LoginResponse.builder()
                    .token(token)
                    .email(request.getEmail())
                    .message("Login successful")
                    .build();
        } catch (InvalidCredentialsException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Error during login: " + e.getMessage());
        }
    }
}
