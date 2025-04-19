package com.loop.api.modules.auth.service;

import com.loop.api.common.exception.*;
import com.loop.api.common.util.UserValidationUtil;
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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtTokenProvider jwtTokenProvider;
	private final RefreshTokenService refreshTokenService;
	private final AuthenticationManager authenticationManager;
	private final EmailService emailService;
	private final VerificationTokenRepository verificationTokenRepository;

	public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder,
					   JwtTokenProvider jwtTokenProvider, RefreshTokenService refreshTokenService,
					   AuthenticationManager authenticationManager,
					   EmailService emailService,
					   VerificationTokenRepository verificationTokenRepository) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtTokenProvider = jwtTokenProvider;
		this.refreshTokenService = refreshTokenService;
		this.authenticationManager = authenticationManager;
		this.emailService = emailService;
		this.verificationTokenRepository = verificationTokenRepository;
	}

	public boolean isEmailRegistered(String email) {
		try {
			UserValidationUtil.validateUniqueUserFields(email, null, null, userRepository, null);
			return false;
		} catch (UserAlreadyExistsException e) {
			return true;
		}
	}

	public String registerUser(RegisterRequest request) {
		UserValidationUtil.validateUniqueUserFields(
				request.getEmail(), request.getUsername(), null, userRepository, null);

		try {
			User user = new User();
			user.setEmail(request.getEmail());
			user.setUsername(request.getUsername());
			user.setPassword(passwordEncoder.encode(request.getPassword()));
			userRepository.save(user);

			String token = UUID.randomUUID().toString();
			VerificationToken vt = new VerificationToken();
			vt.setToken(token);
			vt.setUser(user);
			vt.setExpiryDate(Instant.now().plus(Duration.ofHours(24)));
			verificationTokenRepository.save(vt);

			emailService.sendVerificationEmail(user.getEmail(), token);
			return "User registered successfully";
		} catch (Exception e) {
			throw new RuntimeException("Error registering user: " + e.getMessage());
		}
	}

	public void verifyEmailToken(String token) {
		VerificationToken vt = verificationTokenRepository.findByToken(token)
				.orElseThrow(() -> new InvalidTokenException("Invalid token"));

		if (vt.getExpiryDate().isBefore(Instant.now())) {
			throw new InvalidTokenException("Verification token has expired");
		}

		User user = vt.getUser();
		user.setVerified(true);
		userRepository.save(user);

		verificationTokenRepository.delete(vt);
	}

	public void resendVerificationEmail(String email) {
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UserNotFoundException("User not found"));

		if (user.isVerified()) {
			throw new UserAlreadyVerifiedException("User is already verified");
		}

		verificationTokenRepository.deleteByUser(user);

		VerificationToken token = new VerificationToken();
		token.setToken(UUID.randomUUID().toString());
		token.setUser(user);
		token.setExpiryDate(Instant.now().plus(Duration.ofHours(24)));
		verificationTokenRepository.save(token);

		emailService.sendVerificationEmail(user.getEmail(), token.getToken());
	}

	public LoginResponse loginUser(LoginRequest request) {
		// First, check if the user exists
		Optional<User> userOpt = userRepository.findByEmail(request.getEmail());
		if (userOpt.isEmpty()) {
			throw new UserNotFoundException("This email is not registered. Would you like to sign up instead?");
		}

		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(
							request.getEmail(),
							request.getPassword()
					)
			);

			// Authentication succeeded, get UserPrincipal
			UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

			// Now generate JWT using their email or username
			String accessToken = jwtTokenProvider.generateToken(userPrincipal);

			// Generate refresh token and save to DB
			RefreshToken refreshToken = refreshTokenService.createRefreshToken(userPrincipal.getId());

			return LoginResponse.builder()
					.userId(userPrincipal.getId())
					.accessToken(accessToken)
					.refreshToken(refreshToken.getToken())
					.build();

		} catch (AuthenticationException ex) {
			throw new InvalidCredentialsException("Invalid email or password");
		}
	}

	public LoginResponse refreshAccessToken(String refreshTokenStr) {
		// Validate the refresh token and fetch user details
		RefreshToken oldToken = refreshTokenService.verifyRefreshToken(refreshTokenStr);
		if (oldToken == null) {
			throw new InvalidTokenException("Refresh token is invalid or expired");
		}
		User user = oldToken.getUser();

		// Delete old refresh token and generate a new one
		refreshTokenService.deleteByToken(oldToken.getToken());
		RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getId());

		// Generate new access token
		UserPrincipal userPrincipal = new UserPrincipal(user);
		String newAccessToken = jwtTokenProvider.generateToken(userPrincipal);

		// Return the login response with new tokens
		return LoginResponse.builder()
				.userId(user.getId())
				.accessToken(newAccessToken)
				.refreshToken(newRefreshToken.getToken())
				.build();
	}

	public void logout(String refreshTokenStr) {
		// Validate the refresh token
		RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenStr);
		if (refreshToken == null) {
			throw new InvalidTokenException("Invalid or expired refresh token.");
		}

		// Delete the refresh token from the database to log the user out
		refreshTokenService.deleteByToken(refreshToken.getToken());
	}
}
