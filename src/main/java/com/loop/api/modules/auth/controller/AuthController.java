package com.loop.api.modules.auth.controller;

import com.loop.api.common.constants.ApiRoutes;
import com.loop.api.common.dto.response.StandardResponse;
import com.loop.api.common.exception.InvalidTokenException;
import com.loop.api.modules.auth.dto.LoginRequest;
import com.loop.api.modules.auth.dto.LoginResponse;
import com.loop.api.modules.auth.dto.RegisterRequest;
import com.loop.api.modules.auth.dto.ResendEmailRequest;
import com.loop.api.modules.auth.service.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@Tag(name = "Authentication", description = "Endpoints for user auth related operations")
public class AuthController {

	private final AuthService authService;

	public AuthController(AuthService authService) {
		this.authService = authService;
	}

	@Operation(summary = "Check if email is already registered", description = "Checks whether the provided email is" +
			"already registered.")
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "Email is available"),
			@ApiResponse(responseCode = "400", description = "Email is missing or empty"),
			@ApiResponse(responseCode = "409", description = "Email is already registered")
	})
	@GetMapping(ApiRoutes.Auth.CHECK_EMAIL)
	public ResponseEntity<StandardResponse<String>> checkEmailAvailability(@RequestParam String email) {
		if (email.trim().isEmpty()) {
			throw new IllegalArgumentException("Email must not be empty");
		}

		boolean isEmailRegistered = authService.isEmailRegistered(email);
		if (isEmailRegistered) {
			return ResponseEntity.status(HttpStatus.CONFLICT)
					.body(StandardResponse.error(HttpStatus.CONFLICT, "This email is already registered. Would you " +
							"like to login instead?"));
		}
		return ResponseEntity.ok(StandardResponse.success(HttpStatus.OK, "Email is available", null));
	}

	@Operation(summary = "Register a new user", description = "Creates a user with email, password, and username.")
	@ApiResponses({
			@ApiResponse(responseCode = "201", description = "User created"),
			@ApiResponse(responseCode = "400", description = "Validation failed"),
			@ApiResponse(responseCode = "409", description = "User already exists"),
			@ApiResponse(responseCode = "500", description = "Unexpected server error")
	})
	@PostMapping(ApiRoutes.Auth.SIGNUP)
	public ResponseEntity<StandardResponse<String>> signup(@Valid @RequestBody RegisterRequest request) {
		String response = authService.registerUser(request);
		return ResponseEntity
				.status(HttpStatus.CREATED)
				.body(StandardResponse.success(HttpStatus.CREATED, "User registered", response));
	}

	@Operation(
			summary = "Verify user email",
			description = "Verifies a user's email using a token sent to their email address. "
					+ "If the token is valid and not expired, the user is marked as verified."
	)
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "User successfully verified"),
			@ApiResponse(responseCode = "401", description = "Invalid or expired token"),
			@ApiResponse(responseCode = "500", description = "Unexpected server error")
	})
	@GetMapping(ApiRoutes.Auth.VERIFY)
	public ResponseEntity<StandardResponse<String>> verifyEmail(@RequestParam String token) {
		authService.verifyEmailToken(token);
		return ResponseEntity
				.status(HttpStatus.OK)
				.body(StandardResponse.success(HttpStatus.OK, "User verified", null));
	}

	@Operation(
			summary = "Resend verification email",
			description = "Resends a verification email to a user who has not yet verified their email address. "
					+ "If the user is already verified, a 400 Bad Request error is returned."
	)
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "Verification email resent successfully"),
			@ApiResponse(responseCode = "400", description = "User is already verified, or email is missing"),
			@ApiResponse(responseCode = "404", description = "User not found"),
			@ApiResponse(responseCode = "500", description = "Unexpected server error")
	})
	@PostMapping(ApiRoutes.Auth.RESEND_VERIFICATION)
	public ResponseEntity<StandardResponse<String>> resendVerification(@Valid @RequestBody ResendEmailRequest request) {
		authService.resendVerificationEmail(request.getEmail());
		return ResponseEntity.ok(
				StandardResponse.success(HttpStatus.OK, "Verification email resent", null)
		);
	}

	@Operation(
			summary = "Login user",
			description = "Authenticates a user and returns access and refresh tokens in the response body. "
	)
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "Login successful"),
			@ApiResponse(responseCode = "400", description = "Validation failed"),
			@ApiResponse(responseCode = "401", description = "Invalid credentials"),
			@ApiResponse(responseCode = "404", description = "User not found"),
			@ApiResponse(responseCode = "500", description = "Unexpected server error")
	})
	@PostMapping(value = ApiRoutes.Auth.LOGIN, produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<StandardResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
		LoginResponse response = authService.loginUser(request);

		return ResponseEntity.ok(
				StandardResponse.success(HttpStatus.OK, "Login successful", response)
		);
	}

	@Operation(
			summary = "Refresh access token",
			description = "Validates the refresh token from the request body, issues a new access token, and returns" +
					"new access and refresh tokens."
	)
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "Token refreshed successfully"),
			@ApiResponse(responseCode = "401", description = "Unauthorized - refresh token is missing or invalid"),
			@ApiResponse(responseCode = "500", description = "Unexpected server error")
	})
	@PostMapping(ApiRoutes.Auth.REFRESH)
	public ResponseEntity<StandardResponse<LoginResponse>> refreshToken(
			@RequestBody Map<String, String> requestBody) {

		String refreshTokenStr = requestBody.get("refreshToken");
		if (refreshTokenStr == null || refreshTokenStr.isEmpty()) {
			throw new InvalidTokenException("Refresh token is missing");
		}

		LoginResponse response = authService.refreshAccessToken(refreshTokenStr);
		return ResponseEntity.ok(
				StandardResponse.success(HttpStatus.OK, "Token refreshed", response)
		);
	}

	@Operation(
			summary = "Logout user",
			description = "Invalidates the refresh token from the database to log out the user."
	)
	@ApiResponses({
			@ApiResponse(responseCode = "200", description = "Logged out successfully"),
			@ApiResponse(responseCode = "401", description = "Unauthorized - refresh token is missing or invalid"),
			@ApiResponse(responseCode = "500", description = "Unexpected server error")
	})
	@PostMapping(ApiRoutes.Auth.LOGOUT)
	public ResponseEntity<StandardResponse<String>> logout(@RequestHeader(value = "Authorization", defaultValue = "") String authHeader) {
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			throw new InvalidTokenException("Refresh token is missing or malformed");
		}

		String refreshTokenStr = authHeader.substring(7); // Remove "Bearer "

		authService.logout(refreshTokenStr);

		return ResponseEntity.ok(
				StandardResponse.success(HttpStatus.OK, "Logged out successfully", "Refresh token invalidated")
		);
	}
}