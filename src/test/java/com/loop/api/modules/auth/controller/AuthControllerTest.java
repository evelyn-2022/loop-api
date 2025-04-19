package com.loop.api.modules.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.loop.api.common.constants.ApiRoutes;
import com.loop.api.common.exception.*;
import com.loop.api.modules.auth.dto.LoginRequest;
import com.loop.api.modules.auth.dto.LoginResponse;
import com.loop.api.modules.auth.dto.RegisterRequest;
import com.loop.api.modules.auth.dto.ResendEmailRequest;
import com.loop.api.modules.auth.model.RefreshToken;
import com.loop.api.modules.auth.service.AuthService;
import com.loop.api.modules.user.model.User;
import com.loop.api.testutils.TestUserFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

	@Nested
	@DisplayName("Tests for email availability check")
	class CheckEmailAvailabilityTests {

		@Test
		@DisplayName("Should return 200 OK if email is available")
		void shouldReturnOkIfEmailIsAvailable() throws Exception {
			String email = "new@example.com";

			when(authService.isEmailRegistered(email)).thenReturn(false);

			mockMvc.perform(get(ApiRoutes.Auth.CHECK_EMAIL)
							.param("email", email))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("Email is available"));
		}

		@Test
		@DisplayName("Should return 409 Conflict if email is already registered")
		void shouldReturnConflictIfEmailAlreadyRegistered() throws Exception {
			String email = "exists@example.com";

			when(authService.isEmailRegistered(email)).thenReturn(true);

			mockMvc.perform(get(ApiRoutes.Auth.CHECK_EMAIL)
							.param("email", email))
					.andExpect(status().isConflict())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(409))
					.andExpect(jsonPath("$.message").value("This email is already registered. Would you like to " +
							"login instead?"));
		}

		@Test
		@DisplayName("Should return 400 Bad Request if email is empty")
		void shouldReturnBadRequestIfEmailEmpty() throws Exception {
			mockMvc.perform(get(ApiRoutes.Auth.CHECK_EMAIL)
							.param("email", "   "))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Email must not be empty"));
		}

		@Test
		@DisplayName("Should return 400 Bad Request if email is missing")
		void shouldReturnBadRequestIfEmailMissing() throws Exception {
			mockMvc.perform(get(ApiRoutes.Auth.CHECK_EMAIL))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Missing required parameter: email"));
		}
	}

	@Nested
	@DisplayName("Tests for sign up")
	class RegisterTests {
		@Test
		@DisplayName("Signup: should register user successfully")
		void shouldRegisterUserSuccessfully() throws Exception {
			RegisterRequest request = new RegisterRequest("test@example.comr", "password", "newuser");

			when(authService.registerUser(any(RegisterRequest.class)))
					.thenReturn("User registered successfully");

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
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

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
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
			RegisterRequest request = new RegisterRequest(); // all fields null

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.email").value("Email is required"))
					.andExpect(jsonPath("$.data.username").value("Username is required"))
					.andExpect(jsonPath("$.data.password").value("Password is required"));
		}

		@ParameterizedTest
		@ValueSource(strings = {"not-an-email", "user@invalid", "a@b", "user@.com"})
		@DisplayName("Should return 400 for invalid email format")
		void shouldFailForInvalidEmail(String invalidEmail) throws Exception {
			RegisterRequest req = new RegisterRequest(invalidEmail, "password123", "validUsername");

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(req)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.email").value("Email format is invalid"));
		}

		@Test
		@DisplayName("Should return 400 for short password")
		void shouldFailForShortPassword() throws Exception {
			RegisterRequest req = new RegisterRequest("user@example.com", "123", "validUsername");

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(req)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.password").value("Password must be at least 8 characters"));
		}

		@Test
		@DisplayName("Should return 400 for invalid username characters")
		void shouldFailForInvalidUsername() throws Exception {
			RegisterRequest req = new RegisterRequest("user@example.com", "password123", "<script>");

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(req)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.username").value("Username can only contain letters, numbers and " +
							"underscores"));
		}

		@Test
		@DisplayName("Should return 500 if unexpected error occurs")
		void shouldReturnInternalServerErrorForUnexpectedError() throws Exception {
			RegisterRequest request = new RegisterRequest("new@example.com", "password", "newuser");

			when(authService.registerUser(any(RegisterRequest.class)))
					.thenThrow(new RuntimeException("An unexpected error occurred"));

			mockMvc.perform(post(ApiRoutes.Auth.SIGNUP)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isInternalServerError())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(500))
					.andExpect(jsonPath("$.message").value("An unexpected error occurred"));
		}
	}

	@Nested
	@DisplayName("Tests for email verification")
	class EmailVerificationTests {

		@Test
		@DisplayName("Should return 200 when token is valid")
		void shouldReturnSuccessWhenTokenIsValid() throws Exception {
			String token = "valid-token";

			doNothing().when(authService).verifyEmailToken(token);

			mockMvc.perform(get(ApiRoutes.Auth.VERIFY)
							.param("token", token))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("User verified"))
					.andExpect(jsonPath("$.data").isEmpty());
		}

		@Test
		@DisplayName("Should return 401 Unauthorized when token is invalid")
		void shouldReturnUnauthorizedWhenTokenIsInvalid() throws Exception {
			String token = "invalid-token";

			doThrow(new InvalidTokenException("Invalid token")).when(authService).verifyEmailToken(token);

			mockMvc.perform(get(ApiRoutes.Auth.VERIFY)
							.param("token", token))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Invalid token"));
		}
	}

	@Nested
	@DisplayName("Tests for resending verification email")
	class ResendVerificationTests {

		@Test
		@DisplayName("Should resend verification email successfully")
		void shouldResendVerificationEmailSuccessfully() throws Exception {
			ResendEmailRequest request = new ResendEmailRequest("test@example.com");

			mockMvc.perform(post(ApiRoutes.Auth.RESEND_VERIFICATION)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("Verification email resent"))
					.andExpect(jsonPath("$.data").doesNotExist());

			verify(authService).resendVerificationEmail("test@example.com");
		}

		@Test
		@DisplayName("Should return 400 Bad Request if email is missing")
		void shouldReturnBadRequestIfEmailMissing() throws Exception {
			mockMvc.perform(post(ApiRoutes.Auth.RESEND_VERIFICATION)
							.contentType(MediaType.APPLICATION_JSON)
							.content("{}"))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.email").value("Email is required"));

			verify(authService, never()).resendVerificationEmail(any());
		}

		@Test
		@DisplayName("Should return 400 if user is already verified")
		void shouldReturnBadRequestIfUserAlreadyVerified() throws Exception {
			ResendEmailRequest request = new ResendEmailRequest("verified@example.com");

			doThrow(new UserAlreadyVerifiedException("User is already verified"))
					.when(authService).resendVerificationEmail("verified@example.com");

			mockMvc.perform(post(ApiRoutes.Auth.RESEND_VERIFICATION)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("User is already verified"));
		}
	}

	@Nested
	@DisplayName("Tests for login")
	class LoginTests {
		@Test
		@DisplayName("Login: should authenticate user and return access and refresh tokens")
		void shouldLoginSuccessfully() throws Exception {
			LoginRequest loginRequest = new LoginRequest("test@example.com", "test1234");
			LoginResponse loginResponse = new LoginResponse(1L, "mock-access-token", "mock-refresh-token");

			when(authService.loginUser(any(LoginRequest.class)))
					.thenReturn(loginResponse);

			mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(loginRequest)))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("Login successful"))
					.andExpect(jsonPath("$.data.accessToken").value("mock-access-token"))
					.andExpect(jsonPath("$.data.refreshToken").value("mock-refresh-token"));
		}

		@Test
		@DisplayName("Should return 400 if email or password is missing")
		void shouldReturnBadRequestIfFieldsAreMissing() throws Exception {
			LoginRequest request = new LoginRequest("invalid", null);

			mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.email").value("Email format is invalid"))
					.andExpect(jsonPath("$.data.password").value("Password is required"));
		}

		@Test
		@DisplayName("Should return 400 if login request is missing fields")
		void shouldFailLoginValidation() throws Exception {
			LoginRequest req = new LoginRequest("", "123");

			mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(req)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.data.email").value("Email is required"))
					.andExpect(jsonPath("$.data.password").value("Password must be at least 8 characters"));
		}

		@Test
		@DisplayName("Should return 404 if user not found")
		void shouldReturnNotFoundIfUserNotFound() throws Exception {
			LoginRequest request = new LoginRequest("unknown@example.com", "password");

			when(authService.loginUser(any(LoginRequest.class)))
					.thenThrow(new UserNotFoundException("This email is not registered. Would you like to sign up " +
							"instead?"));

			mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isNotFound())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(404))
					.andExpect(jsonPath("$.message").value("This email is not registered. Would you like to sign up " +
							"instead?"));
		}

		@Test
		@DisplayName("Should return 401 if password is incorrect")
		void shouldReturnUnauthorizedIfPasswordIncorrect() throws Exception {
			LoginRequest request = new LoginRequest("test@example.com", "wrongpassword");

			when(authService.loginUser(any(LoginRequest.class)))
					.thenThrow(new InvalidCredentialsException("Invalid email or password"));

			mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Invalid email or password"));
		}

		@Test
		@DisplayName("Should return 500 if unexpected error occurs")
		void shouldReturnInternalServerErrorWhenUnexpectedExceptionOccurs() throws Exception {
			LoginRequest request = new LoginRequest("test@example.com", "password");

			when(authService.loginUser(any(LoginRequest.class)))
					.thenThrow(new RuntimeException("An unexpected error occurred"));

			mockMvc.perform(post(ApiRoutes.Auth.LOGIN)
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isInternalServerError())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(500))
					.andExpect(jsonPath("$.message").value("An unexpected error occurred"));
		}
	}

	@Nested
	@DisplayName("Tests for refreshToken")
	class RefreshTokenTests {

		@Test
		@DisplayName("Refresh: should return new access token and refresh token")
		void shouldRefreshTokenSuccessfully() throws Exception {
			// Prepare user and tokens
			User user = TestUserFactory.regularUser(1L);
			RefreshToken oldToken = new RefreshToken();
			oldToken.setToken("old-refresh-token");
			oldToken.setUser(user);

			RefreshToken newToken = new RefreshToken();
			newToken.setToken("new-refresh-token");
			newToken.setUser(user);

			// Mock the AuthService method
			when(authService.refreshAccessToken(eq("old-refresh-token")))
					.thenReturn(LoginResponse.builder()
							.accessToken("new-access-token")
							.refreshToken("new-refresh-token")
							.userId(1L)
							.build());

			// Perform the test with the refresh token in the request body
			mockMvc.perform(post(ApiRoutes.Auth.REFRESH)
							.contentType(MediaType.APPLICATION_JSON)
							.content("{\"refreshToken\": \"old-refresh-token\"}"))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("Token refreshed"))
					.andExpect(jsonPath("$.data.accessToken").value("new-access-token"))
					.andExpect(jsonPath("$.data.refreshToken").value("new-refresh-token"))
					.andExpect(jsonPath("$.data.userId").value(1));
		}


		@Test
		@DisplayName("Refresh: should return 401 if refresh token is missing")
		void shouldReturn401IfTokenMissing() throws Exception {
			mockMvc.perform(post(ApiRoutes.Auth.REFRESH)
							.contentType(MediaType.APPLICATION_JSON)
							.content("{}")) // Empty JSON body
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Refresh token is missing"));
		}

		@Test
		@DisplayName("Refresh: should return 401 if refresh token is empty")
		void shouldReturn401IfTokenEmpty() throws Exception {
			mockMvc.perform(post(ApiRoutes.Auth.REFRESH)
							.contentType(MediaType.APPLICATION_JSON)
							.content("{\"refreshToken\": \"\"}"))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Refresh token is missing"));
		}

		@Test
		@DisplayName("Refresh: should return 401 if token is invalid/expired")
		void shouldReturn401IfTokenInvalidOrExpired() throws Exception {
			when(authService.refreshAccessToken(eq("expired-token")))
					.thenThrow(new InvalidTokenException("Refresh token is invalid or expired"));

			mockMvc.perform(post(ApiRoutes.Auth.REFRESH)
							.contentType(MediaType.APPLICATION_JSON)
							.content("{\"refreshToken\": \"expired-token\"}"))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Refresh token is invalid or expired"));
		}
	}

	@Nested
	@DisplayName("Logout Tests")
	class LogoutTests {

		@Test
		@DisplayName("should successfully log out and invalidate the refresh token")
		void shouldLogOutSuccessfully() throws Exception {
			// Mocking the AuthService.logout method
			doNothing().when(authService).logout(eq("valid-refresh-token"));

			// Perform the logout request with a valid Bearer token
			mockMvc.perform(post(ApiRoutes.Auth.LOGOUT)
							.header("Authorization", "Bearer valid-refresh-token"))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("Logged out successfully"))
					.andExpect(jsonPath("$.data").value("Refresh token invalidated"));
		}

		@Test
		@DisplayName("should return 401 if the refresh token is missing")
		void shouldReturn401IfTokenIsMissing() throws Exception {
			// Perform the logout request without a Bearer token
			mockMvc.perform(post(ApiRoutes.Auth.LOGOUT)
							.header("Authorization", "InvalidToken"))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Refresh token is missing or malformed"));
		}

		@Test
		@DisplayName("Should return 401 if the Authorization header is malformed")
		void shouldReturn401IfAuthorizationHeaderIsMalformed() throws Exception {
			// Perform the logout request with an Authorization header that doesn't start with "Bearer "
			mockMvc.perform(post(ApiRoutes.Auth.LOGOUT)
							.header("Authorization", "Basic abc123"))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Refresh token is missing or malformed"));
		}

		@Test
		@DisplayName("should return 401 if the refresh token is null")
		void shouldReturn401IfTokenIsNull() throws Exception {
			// Perform the logout request with a missing Authorization header
			mockMvc.perform(post(ApiRoutes.Auth.LOGOUT))
					.andExpect(status().isUnauthorized())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(401))
					.andExpect(jsonPath("$.message").value("Unauthorized: Refresh token is missing or malformed"));
		}
	}
}