package com.loop.api.modules.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.loop.api.common.exception.UserAlreadyExistsException;
import com.loop.api.modules.auth.dto.LoginRequest;
import com.loop.api.modules.auth.dto.LoginResponse;
import com.loop.api.modules.auth.dto.RegisterRequest;
import com.loop.api.modules.auth.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Tag("UnitTest")
@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    // Tests for /signup
    @Test
    @DisplayName("Signup: should register user successfully")
    void shouldRegisterUserSuccessfully() throws Exception {
        RegisterRequest request = new RegisterRequest("test@example.comr", "password", "newuser");

        when(authService.registerUser(any(RegisterRequest.class)))
                .thenReturn("User registered successfully");

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.code").value(201))
                .andExpect(jsonPath("$.message").value("User registered"))
                .andExpect(jsonPath("$.data").value("User registered successfully"));
    }

    @Test
    @DisplayName("Should return 409 Conflict if user already exists")
    void shouldReturnConflictIfUserExists() throws Exception {
        RegisterRequest request = new RegisterRequest("exists@example.com", "password", "existinguser");

        when(authService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new UserAlreadyExistsException("User with email 'exists@example.com' already exists."));

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value("ERROR"))
                .andExpect(jsonPath("$.code").value(409))
                .andExpect(jsonPath("$.message").value("User with email 'exists@example.com' already exists."));
    }

    @Test
    @DisplayName("Should return 400 Bad Request if fields are missing")
    void shouldReturnBadRequestForMissingFields() throws Exception {
        RegisterRequest request = new RegisterRequest();

        when(authService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new IllegalArgumentException("Email, username, and password cannot be empty or null"));

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("ERROR"))
                .andExpect(jsonPath("$.code").value(400))
                .andExpect(jsonPath("$.message").value("Email, username, and password cannot be empty or null"));
    }

    @Test
    @DisplayName("Should return 500 if unexpected error occurs")
    void shouldReturnInternalServerErrorForUnexpectedError() throws Exception {
        RegisterRequest request = new RegisterRequest("new@example.com","password","newuser");

        when(authService.registerUser(any(RegisterRequest.class)))
                .thenThrow(new RuntimeException("An unexpected error occurred"));

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value("ERROR"))
                .andExpect(jsonPath("$.code").value(500))
                .andExpect(jsonPath("$.message").value("An unexpected error occurred"));
    }

    // Tests for /login

    @Test
    @DisplayName("Login: should authenticate user and return token")
    void shouldLoginSuccessfully() throws Exception {
        LoginRequest loginRequest = new LoginRequest("test@example.com", "test123");
        LoginResponse loginResponse = new LoginResponse("abc123");

        when(authService.loginUser(any(LoginRequest.class)))
                .thenReturn(loginResponse);

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.code").value(200))
                .andExpect(jsonPath("$.message").value("Login successful"))
                .andExpect(jsonPath("$.data.token").value("abc123"));
    }
}