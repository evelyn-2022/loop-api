package com.loop.api.modules.auth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class EmailService {

	private final JavaMailSender mailSender;
	private final String baseUrl;
	private final String contextPath;

	public EmailService(JavaMailSender mailSender,
						@Value("${app.base-url}") String baseUrl,
						@Value("${server.servlet.context-path}") String contextPath) {
		this.mailSender = mailSender;
		this.baseUrl = baseUrl;
		this.contextPath = contextPath;
	}

	@Async
	public void sendVerificationEmail(String to, String token) {
		String link = baseUrl + contextPath + "/auth/verify?token=" + token;

		SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(to);
		message.setSubject("Confirm your email");
		message.setText("Click the link to verify your email: " + link);

		try {
			mailSender.send(message);
		} catch (Exception e) {
			log.error("❌ Failed to send verification email to {}", to, e);
		}
	}
}
