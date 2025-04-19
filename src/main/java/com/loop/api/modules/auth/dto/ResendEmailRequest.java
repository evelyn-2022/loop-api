package com.loop.api.modules.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ResendEmailRequest {
	@NotBlank(message = "Email is required")
	private String email;
}
