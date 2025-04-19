package com.loop.api.modules.auth.service;

import com.loop.api.common.exception.*;
import com.loop.api.modules.auth.dto.LoginRequest;
import com.loop.api.modules.auth.dto.LoginResponse;
import com.loop.api.modules.auth.dto.RegisterRequest;
import com.loop.api.modules.auth.model.RefreshToken;
import com.loop.api.modules.auth.model.VerificationToken;
import com.loop.api.modules.auth.repository.VerificationTokenRepository;
import com.loop.api.modules.user.model.User;
import com.loop.api.modules.user.repository.UserRepository;
import com.loop.api.security.JwtTokenProvider;
import com.loop.api.security.UserPrincipal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@Tag("UnitTest")
@ExtendWith(MockitoExtension.class)
public class AuthServiceTest {
	@Mock
	private UserRepository userRepository;
	@Mock
	private VerificationTokenRepository verificationTokenRepository;
	@Mock
	private PasswordEncoder passwordEncoder;
	@Mock
	private AuthenticationManager authenticationManager;
	@Mock
	private RefreshTokenService refreshTokenService;
	@Mock
	private EmailService emailService;
	@Mock
	private JwtTokenProvider jwtTokenProvider;

	@InjectMocks
	private AuthService authService;

	@Nested
	@DisplayName("Tests for signup service")
	class RegisterTests {

		@Test
		@DisplayName("Should register user successfully")
		void shouldRegisterUserSuccessfully() {
			RegisterRequest request = new RegisterRequest("new@example.com", "password", "newuser");

			when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
			when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
			when(passwordEncoder.encode("password")).thenReturn("encodedPass");

			String result = authService.registerUser(request);

			assertEquals("User registered successfully", result);
			verify(userRepository).save(any(User.class));
			verify(verificationTokenRepository).save(any(VerificationToken.class));
			verify(emailService).sendVerificationEmail(eq("new@example.com"), anyString());
		}

		@Test
		@DisplayName("Should throw UserAlreadyExistsException when email already exists")
		void shouldThrowUserAlreadyExistsExceptionIfEmailExists() {
			RegisterRequest request = new RegisterRequest("exists@example.com", "password", "existinguser");

			User existingUser = new User();
			existingUser.setId(123L);

			when(userRepository.findByEmail("exists@example.com"))
					.thenReturn(Optional.of(existingUser));

			assertThrows(UserAlreadyExistsException.class, () -> authService.registerUser(request));

			verify(userRepository, never()).save(any());
			verify(verificationTokenRepository, never()).save(any());
			verify(emailService, never()).sendVerificationEmail(any(), any());
		}

		@Test
		@DisplayName("Should throw UserAlreadyExistsException when username already exists")
		void shouldThrowUserAlreadyExistsExceptionIfUsernameExists() {
			RegisterRequest request = new RegisterRequest("exists@example.com", "password", "existinguser");

			User existingUser = new User();
			existingUser.setId(123L);

			when(userRepository.findByEmail("exists@example.com")).thenReturn(Optional.empty());
			when(userRepository.findByUsername("existinguser")).thenReturn(Optional.of(existingUser));

			assertThrows(UserAlreadyExistsException.class, () -> authService.registerUser(request));

			verify(userRepository, never()).save(any());
			verify(verificationTokenRepository, never()).save(any());
			verify(emailService, never()).sendVerificationEmail(any(), any());
		}

		@Test
		@DisplayName("Should throw RuntimeException when saving user fails unexpectedly")
		void shouldThrowRuntimeExceptionOnUnexpectedSaveFailure() {
			RegisterRequest request = new RegisterRequest("new@example.com", "password", "newuser");

			when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
			when(userRepository.findByUsername("newuser")).thenReturn(Optional.empty());
			when(passwordEncoder.encode("password")).thenReturn("encoded");

			doThrow(new RuntimeException("DB error")).when(userRepository).save(any());

			RuntimeException ex = assertThrows(RuntimeException.class,
					() -> authService.registerUser(request));

			assertTrue(ex.getMessage().contains("Error registering user"));

			verify(verificationTokenRepository, never()).save(any());
			verify(emailService, never()).sendVerificationEmail(any(), any());
		}
	}


	@Nested
	@DisplayName("Tests for email verification")
	class EmailVerificationTests {

		@Test
		@DisplayName("Should verify user and delete token if token is valid and not expired")
		void shouldVerifyUserSuccessfully() {
			String token = "valid-token";

			User user = new User();
			user.setVerified(false);

			VerificationToken verificationToken = new VerificationToken();
			verificationToken.setToken(token);
			verificationToken.setUser(user);
			verificationToken.setExpiryDate(Instant.now().plus(Duration.ofHours(1)));

			when(verificationTokenRepository.findByToken(token))
					.thenReturn(Optional.of(verificationToken));

			authService.verifyEmailToken(token);

			assertTrue(user.isVerified(), "User should be marked as verified");
			verify(userRepository).save(user);
			verify(verificationTokenRepository).delete(verificationToken);
		}

		@Test
		@DisplayName("Should throw InvalidTokenException when token is not found")
		void shouldThrowWhenTokenNotFound() {
			String token = "invalid-token";

			when(verificationTokenRepository.findByToken(token))
					.thenReturn(Optional.empty());

			assertThrows(InvalidTokenException.class,
					() -> authService.verifyEmailToken(token));
		}

		@Test
		@DisplayName("Should throw InvalidTokenException when token is expired")
		void shouldThrowWhenTokenIsExpired() {
			String token = "expired-token";

			User user = new User();
			VerificationToken expiredToken = new VerificationToken();
			expiredToken.setToken(token);
			expiredToken.setUser(user);
			expiredToken.setExpiryDate(Instant.now().minus(Duration.ofHours(1)));

			when(verificationTokenRepository.findByToken(token))
					.thenReturn(Optional.of(expiredToken));

			assertThrows(InvalidTokenException.class,
					() -> authService.verifyEmailToken(token));
		}
	}

	@Nested
	@DisplayName("Tests for resending verification email")
	class ResendVerificationTests {

		@Test
		@DisplayName("Should resend verification email if user is not verified")
		void shouldResendVerificationEmailSuccessfully() {
			User user = new User();
			user.setEmail("test@example.com");
			user.setVerified(false);

			when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

			authService.resendVerificationEmail("test@example.com");

			verify(verificationTokenRepository).deleteByUser(user);
			verify(verificationTokenRepository).save(any(VerificationToken.class));
			verify(emailService).sendVerificationEmail(eq("test@example.com"), anyString());
		}

		@Test
		@DisplayName("Should throw UserNotFoundException if user is not found")
		void shouldThrowIfUserNotFound() {
			when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

			assertThrows(UserNotFoundException.class, () ->
					authService.resendVerificationEmail("missing@example.com"));

			verifyNoInteractions(verificationTokenRepository);
			verifyNoInteractions(emailService);
		}

		@Test
		@DisplayName("Should throw UserAlreadyVerifiedException if user is already verified")
		void shouldThrowIfUserAlreadyVerified() {
			User user = new User();
			user.setEmail("verified@example.com");
			user.setVerified(true);

			when(userRepository.findByEmail("verified@example.com")).thenReturn(Optional.of(user));

			UserAlreadyVerifiedException ex = assertThrows(UserAlreadyVerifiedException.class, () ->
					authService.resendVerificationEmail("verified@example.com"));

			assertTrue(ex.getMessage().contains("already verified"));

			verify(verificationTokenRepository, never()).deleteByUser(any());
			verify(emailService, never()).sendVerificationEmail(any(), any());
		}
	}

	@Nested
	@DisplayName("Tests for login service")
	class LoginTests {
		@Test
		@DisplayName("Should return token when login is successful")
		void shouldLoginSuccessfully() {
			LoginRequest request = new LoginRequest("user@example.com", "password");

			User user = new User();
			user.setEmail("user@example.com");
			user.setPassword("hashedPassword");
			user.setUsername("some-username");

			UserPrincipal userPrincipal = new UserPrincipal(user);

			Authentication authentication = mock(Authentication.class);
			when(authentication.getPrincipal()).thenReturn(userPrincipal);

			RefreshToken refreshToken = new RefreshToken();
			refreshToken.setToken("refresh-token");
			refreshToken.setUser(user);

			when(refreshTokenService.createRefreshToken(user.getId()))
					.thenReturn(refreshToken);


			when(userRepository.findByEmail("user@example.com"))
					.thenReturn(Optional.of(user));

			when(authenticationManager.authenticate(any()))
					.thenReturn(authentication);

			when(jwtTokenProvider.generateToken(userPrincipal))
					.thenReturn("jwt-token");

			LoginResponse response = authService.loginUser(request);

			assertEquals("jwt-token", response.getAccessToken());
			verify(authenticationManager).authenticate(any());
			verify(jwtTokenProvider).generateToken(userPrincipal);
		}

		@Test
		@DisplayName("Should throw UserNotFoundException if user does not exist")
		void shouldThrowIfUserNotFound() {
			LoginRequest request = new LoginRequest("notfound@example.com", "password");

			when(userRepository.findByEmail("notfound@example.com"))
					.thenReturn(Optional.empty());

			assertThrows(UserNotFoundException.class, () -> authService.loginUser(request));
		}

		@Test
		@DisplayName("Should throw InvalidCredentialsException if password is incorrect")
		void shouldThrowIfPasswordIncorrect() {
			LoginRequest request = new LoginRequest("user@example.com", "wrongPassword");

			User user = new User();
			user.setEmail("user@example.com");
			user.setPassword("hashedPassword");

			when(userRepository.findByEmail("user@example.com"))
					.thenReturn(Optional.of(user));

			when(authenticationManager.authenticate(any()))
					.thenThrow(new BadCredentialsException("Bad credentials"));

			assertThrows(InvalidCredentialsException.class, () -> authService.loginUser(request));
		}

		@Test
		@DisplayName("Should throw RuntimeException if unexpected exception occurs")
		void shouldThrowRuntimeExceptionOnUnexpectedError() {
			LoginRequest request = new LoginRequest("user@example.com", "password");

			User user = new User();
			user.setEmail("user@example.com");
			user.setPassword("hashedPassword");

			when(userRepository.findByEmail("user@example.com"))
					.thenReturn(Optional.of(user));

			when(authenticationManager.authenticate(any()))
					.thenThrow(new RuntimeException("DB error"));

			RuntimeException exception = assertThrows(RuntimeException.class,
					() -> authService.loginUser(request));

			assertTrue(exception.getMessage().contains("DB error"));
		}
	}

	@Nested
	@DisplayName("Tests for refresh token service")
	class RefreshTokenTests {

		@Test
		@DisplayName("Should refresh token successfully")
		void shouldRefreshTokenSuccessfully() {
			// Arrange - create a mock user and refresh token
			User user = new User();
			user.setId(1L);
			user.setEmail("user@example.com");

			RefreshToken oldToken = new RefreshToken();
			oldToken.setToken("old-refresh-token");
			oldToken.setUser(user);

			RefreshToken newToken = new RefreshToken();
			newToken.setToken("new-refresh-token");
			newToken.setUser(user);

			LoginResponse loginResponse = new LoginResponse();
			loginResponse.setAccessToken("new-access-token");
			loginResponse.setRefreshToken(newToken.getToken());
			loginResponse.setUserId(user.getId());

			// Mocks
			when(refreshTokenService.verifyRefreshToken("old-refresh-token")).thenReturn(oldToken);
			doNothing().when(refreshTokenService).deleteByToken("old-refresh-token");
			when(refreshTokenService.createRefreshToken(user.getId())).thenReturn(newToken);
			when(jwtTokenProvider.generateToken(any(UserPrincipal.class))).thenReturn("new-access-token");

			// Act
			LoginResponse result = authService.refreshAccessToken("old-refresh-token");

			// Assert
			assertNotNull(result);
			assertEquals("new-access-token", result.getAccessToken());
			assertEquals("new-refresh-token", result.getRefreshToken());
			assertEquals(user.getId(), result.getUserId());

			verify(refreshTokenService).deleteByToken("old-refresh-token");
			verify(refreshTokenService).createRefreshToken(user.getId());
		}

		@Test
		@DisplayName("Should throw InvalidTokenException when the refresh token is invalid or expired")
		void shouldThrowInvalidTokenExceptionWhenTokenInvalid() {
			when(refreshTokenService.verifyRefreshToken("invalid-refresh-token"))
					.thenThrow(new InvalidTokenException("Refresh token is invalid or expired"));

			InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> {
				authService.refreshAccessToken("invalid-refresh-token");
			});

			assertEquals("Refresh token is invalid or expired", exception.getMessage());
		}

		@Test
		@DisplayName("Should throw InvalidTokenException when the refresh token is null")
		void shouldThrowInvalidTokenExceptionWhenTokenIsNull() {
			InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> {
				authService.refreshAccessToken(null);
			});

			assertEquals("Refresh token is invalid or expired", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("Tests for logout functionality")
	class LogoutTests {

		@Test
		@DisplayName("Should log out successfully with a valid refresh token")
		void shouldLogOutSuccessfullyWithValidToken() {
			String validToken = "valid-refresh-token";
			RefreshToken refreshToken = new RefreshToken();
			refreshToken.setToken(validToken);

			when(refreshTokenService.verifyRefreshToken(validToken)).thenReturn(refreshToken);
			doNothing().when(refreshTokenService).deleteByToken(validToken);

			authService.logout(validToken);

			verify(refreshTokenService).deleteByToken(validToken);
		}

		@Test
		@DisplayName("Should throw InvalidTokenException when the refresh token is invalid or expired")
		void shouldThrowInvalidTokenExceptionWhenTokenIsInvalid() {
			String invalidToken = "invalid-refresh-token";
			when(refreshTokenService.verifyRefreshToken(invalidToken)).thenReturn(null);

			InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> {
				authService.logout(invalidToken);
			});

			assertEquals("Invalid or expired refresh token.", exception.getMessage());
		}

		@Test
		@DisplayName("Should throw InvalidTokenException when the refresh token is missing")
		void shouldThrowInvalidTokenExceptionWhenTokenIsMissing() {
			InvalidTokenException exception = assertThrows(InvalidTokenException.class, () -> {
				authService.logout(null);
			});

			assertEquals("Invalid or expired refresh token.", exception.getMessage());
		}
	}

	@Nested
	@DisplayName("Tests for email registration check")
	class EmailRegistrationTests {

		@Test
		@DisplayName("Should return false when email is not registered")
		void shouldReturnFalseWhenEmailNotRegistered() {
			String email = "new@example.com";

			when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

			boolean result = authService.isEmailRegistered(email);

			assertFalse(result);
		}

		@Test
		@DisplayName("Should return true when email check throws UserAlreadyExistsException")
		void shouldReturnTrueWhenEmailCheckThrowsException() {
			String email = "exists@example.com";

			when(userRepository.findByEmail(email)).thenThrow(new UserAlreadyExistsException("User already exists"));

			boolean result = authService.isEmailRegistered(email);

			assertTrue(result);
		}
	}
}

