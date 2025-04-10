package com.loop.api.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.loop.api.common.dto.response.StandardResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class UnauthorizedHandler implements AuthenticationEntryPoint {

	private final ObjectMapper objectMapper;

	public UnauthorizedHandler(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Override
	public void commence(HttpServletRequest request,
						 HttpServletResponse response,
						 AuthenticationException authException) throws IOException {

		StandardResponse<Void> errorResponse = StandardResponse.error(
				HttpStatus.UNAUTHORIZED,
				"Unauthorized: " + authException.getMessage()
		);

		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType("application/json");
		response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
	}
}