package com.loop.api.modules.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jayway.jsonpath.JsonPath;
import com.loop.api.common.constants.ApiRoutes;
import com.loop.api.modules.auth.dto.LoginRequest;
import com.loop.api.modules.auth.dto.RegisterRequest;
import com.loop.api.modules.auth.model.RefreshToken;
import com.loop.api.modules.auth.model.VerificationToken;
import com.loop.api.modules.auth.repository.RefreshTokenRepository;
import com.loop.api.modules.auth.repository.VerificationTokenRepository;
import com.loop.api.modules.auth.service.EmailService;
import com.loop.api.modules.auth.service.RefreshTokenService;
import com.loop.api.modules.user.model.User;
import com.loop.api.modules.user.repository.UserRepository;
import com.loop.api.testutils.PostgresTestContainerConfig;
import com.loop.api.testutils.TestUserFactory;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Tag("IntegrationTest")
@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestContainerConfig.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class AuthControllerIT {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private VerificationTokenRepository verificationTokenRepository;

	@Autowired
	private RefreshTokenService refreshTokenService;

	@Autowired
	private ObjectMapper objectMapper;

	@MockitoBean
	private EmailService emailService;

	@BeforeEach
	void setUp() {
		doNothing().when(emailService).sendVerificationEmail(anyString(), anyString());
		refreshTokenRepository.deleteAll();
		verificationTokenRepository.deleteAll();
		userRepository.deleteAll();
	}

	@Test
	@DisplayName("Should register new user successfully")
	void shouldRegisterUserSuccessfully() throws Exception {
		RegisterRequest request = new RegisterRequest();
		request.setEmail("test@example.com");
		request.setPassword("securePass123");
		request.setUsername("test123");

		mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.status").value("SUCCESS"))
				.andExpect(jsonPath("$.code").value(201))
				.andExpect(jsonPath("$.message").value("User registered"))
				.andExpect(jsonPath("$.data").value("User registered successfully"));

		// Verify user exists in DB
		Optional<User> userOpt = userRepository.findByEmail("test@example.com");
		assertTrue(userOpt.isPresent());
		assertEquals("test123", userOpt.get().getUsername());
	}

	@Test
	@DisplayName("Should verify user successfully through /verify endpoint")
	void shouldVerifyUserSuccessfullyThroughVerifyEndpoint() throws Exception {
		// Arrange: create and save a user
		User user = new User();
		user.setEmail("verifyme@example.com");
		user.setUsername("verifyme");
		user.setPassword("securePass123");
		user.setVerified(false);
		user = userRepository.save(user);

		// Create a valid verification token
		VerificationToken token = new VerificationToken();
		token.setToken("valid-token");
		token.setUser(user);
		token.setExpiryDate(Instant.now().plus(Duration.ofHours(24)));
		verificationTokenRepository.save(token);

		// Act: call the /verify endpoint
		mockMvc.perform(get(ApiRoutes.Auth.VERIFY)
						.param("token", token.getToken()))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("SUCCESS"))
				.andExpect(jsonPath("$.code").value(200))
				.andExpect(jsonPath("$.message").value("User verified"))
				.andExpect(jsonPath("$.data").doesNotExist());

		// Assert: user is verified in DB
		Optional<User> updatedUser = userRepository.findById(user.getId());
		assertTrue(updatedUser.isPresent());
		assertTrue(updatedUser.get().isVerified(), "User should be verified");

		// Assert: verification token is deleted
		assertTrue(verificationTokenRepository.findByToken(token.getToken()).isEmpty(),
				"Token should be deleted after verification");
	}

	@Test
	@DisplayName("Should login successfully and return access token + refresh token cookie")
	void shouldLoginSuccessfully() throws Exception {
		// Arrange - create user in DB
		User user = new User();
		user.setEmail("login@example.com");
		user.setPassword(new BCryptPasswordEncoder().encode("securePass123"));
		user.setUsername("loginUser");
		user.setAdmin(false);
		userRepository.save(user);

		// Act + Assert
		LoginRequest request = new LoginRequest();
		request.setEmail("login@example.com");
		request.setPassword("securePass123");

		mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("SUCCESS"))
				.andExpect(jsonPath("$.code").value(200))
				.andExpect(jsonPath("$.message").value("Login successful"))
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty())
				.andExpect(jsonPath("$.data.refreshToken").isNotEmpty())
				.andExpect(jsonPath("$.data.userId").value(user.getId()))
				.andReturn();

		// Assert refresh token saved in DB
		List<RefreshToken> tokens = refreshTokenRepository.findAll();
		assertEquals(1, tokens.size());
		assertEquals(user.getId(), tokens.getFirst().getUser().getId());
	}

	@Test
	@DisplayName("Should refresh token successfully with valid refresh token in Authorization header")
	void shouldRefreshTokenSuccessfully() throws Exception {
		// Arrange - create and save user
		User user = TestUserFactory.regularUser(null);
		user = userRepository.save(user);

		// Create and persist refresh token
		RefreshToken oldRefreshToken = refreshTokenService.createRefreshToken(user.getId());
		assertTrue(refreshTokenRepository.findByToken(oldRefreshToken.getToken()).isPresent());

		// Act - perform request with refresh token in body
		MvcResult result = mockMvc.perform(post(ApiRoutes.Auth.REFRESH)
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"refreshToken\": \"" + oldRefreshToken.getToken() + "\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("SUCCESS"))
				.andExpect(jsonPath("$.code").value(200))
				.andExpect(jsonPath("$.message").value("Token refreshed"))
				.andExpect(jsonPath("$.data.accessToken").isNotEmpty())
				.andExpect(jsonPath("$.data.refreshToken").isNotEmpty())
				.andExpect(jsonPath("$.data.userId").value(user.getId()))
				.andReturn();

		// Extract the new refresh token from response body
		String jsonResponse = result.getResponse().getContentAsString();
		String newRefreshTokenValue = JsonPath.read(jsonResponse, "$.data.refreshToken");

		// Assert - old token is deleted
		assertFalse(refreshTokenRepository.findByToken(oldRefreshToken.getToken()).isPresent());

		// Assert - new token is saved
		Optional<RefreshToken> newTokenOpt = refreshTokenRepository.findByToken(newRefreshTokenValue);
		assertTrue(newTokenOpt.isPresent(), "New refresh token should be saved in DB");

		// Assert - associated user is still correct
		assertEquals(user.getId(), newTokenOpt.get().getUser().getId(), "New token should belong to same user");
	}

	@Test
	@DisplayName("Logout: should return 200 if refresh token is valid")
	void shouldReturn200IfTokenIsValid() throws Exception {
		// Arrange - valid refresh token
		User user = TestUserFactory.regularUser(null);
		user = userRepository.save(user);

		// Create and persist a valid refresh token
		RefreshToken validRefreshToken = refreshTokenService.createRefreshToken(user.getId());
		assertTrue(refreshTokenRepository.findByToken(validRefreshToken.getToken()).isPresent());

		// Act - perform the logout request with the valid refresh token in the Authorization header
		mockMvc.perform(post(ApiRoutes.Auth.LOGOUT)
						.header("Authorization", "Bearer " + validRefreshToken.getToken())) // Valid Bearer token
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("SUCCESS"))
				.andExpect(jsonPath("$.code").value(200))
				.andExpect(jsonPath("$.message").value("Logged out successfully"))
				.andExpect(jsonPath("$.data").value("Refresh token invalidated"));

		// Assert - Check if the refresh token was deleted after logout
		assertFalse(refreshTokenRepository.findByToken(validRefreshToken.getToken()).isPresent(),
				"Refresh token should be deleted after logout");
	}
}