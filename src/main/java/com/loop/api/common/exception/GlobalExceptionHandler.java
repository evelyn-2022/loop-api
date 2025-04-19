package com.loop.api.common.exception;

import com.loop.api.common.dto.response.StandardResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<StandardResponse<String>> handleIllegalArgumentException(IllegalArgumentException ex) {
		return ResponseEntity.badRequest().body(StandardResponse.error(HttpStatus.BAD_REQUEST, ex.getMessage()));
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<StandardResponse<Map<String, String>>> handleValidationErrors(MethodArgumentNotValidException ex) {
		Map<String, String> errors = new HashMap<>();

		ex.getBindingResult().getFieldErrors().forEach(error ->
				errors.put(error.getField(), error.getDefaultMessage())
		);

		return ResponseEntity.badRequest().body(
				StandardResponse.error(HttpStatus.BAD_REQUEST, "Validation failed", errors)
		);
	}

	@ExceptionHandler(UserAlreadyExistsException.class)
	public ResponseEntity<StandardResponse<Void>> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
		return ResponseEntity
				.status(HttpStatus.CONFLICT)
				.body(StandardResponse.error(HttpStatus.CONFLICT, ex.getMessage()));
	}

	@ExceptionHandler(InvalidCredentialsException.class)
	public ResponseEntity<StandardResponse<Void>> handleInvalidCredentialsException(InvalidCredentialsException ex) {
		return ResponseEntity
				.status(HttpStatus.UNAUTHORIZED)
				.body(StandardResponse.error(HttpStatus.UNAUTHORIZED, ex.getMessage()));
	}

	@ExceptionHandler(UserNotFoundException.class)
	public ResponseEntity<StandardResponse<Void>> handleUserNotFoundException(UserNotFoundException ex) {
		return ResponseEntity
				.status(HttpStatus.NOT_FOUND)
				.body(StandardResponse.error(HttpStatus.NOT_FOUND, ex.getMessage()));
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<StandardResponse<Void>> handleAccessDeniedException(AccessDeniedException ex) {
		return ResponseEntity
				.status(HttpStatus.FORBIDDEN)
				.body(StandardResponse.error(HttpStatus.FORBIDDEN, "Forbidden: You do not have permission."));
	}

	@ExceptionHandler(InvalidTokenException.class)
	public ResponseEntity<StandardResponse<Void>> handleInvalidTokenException(InvalidTokenException ex) {
		return ResponseEntity
				.status(HttpStatus.UNAUTHORIZED)
				.body(StandardResponse.error(HttpStatus.UNAUTHORIZED, "Unauthorized: " + ex.getMessage()));
	}

	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ResponseEntity<StandardResponse<String>> handleMissingParams(MissingServletRequestParameterException ex) {
		String paramName = ex.getParameterName();
		String message = String.format("Missing required parameter: %s", paramName);
		return ResponseEntity.badRequest().body(StandardResponse.error(HttpStatus.BAD_REQUEST, message));
	}

	@ExceptionHandler(UserAlreadyVerifiedException.class)
	public ResponseEntity<StandardResponse<Void>> handleUserAlreadyVerified(UserAlreadyVerifiedException ex) {
		return ResponseEntity
				.status(HttpStatus.BAD_REQUEST)
				.body(StandardResponse.error(HttpStatus.BAD_REQUEST, ex.getMessage()));
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<StandardResponse<Void>> handleGlobalException(Exception ex) {
		return ResponseEntity
				.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(StandardResponse.error(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred"));
	}
}

