package com.loop.api.scheduler;

import com.loop.api.modules.auth.model.RefreshToken;
import com.loop.api.modules.auth.model.VerificationToken;
import com.loop.api.modules.auth.repository.RefreshTokenRepository;
import com.loop.api.modules.auth.repository.VerificationTokenRepository;
import com.loop.api.modules.user.model.User;
import com.loop.api.modules.user.repository.UserRepository;
import com.loop.api.testutils.PostgresTestContainerConfig;
import com.loop.api.testutils.TestUserFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("IntegrationTest")
@SpringBootTest
@Import(PostgresTestContainerConfig.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TokenCleanupJobIT {

	@Autowired
	private RefreshTokenRepository refreshTokenRepository;

	@Autowired
	private VerificationTokenRepository verificationTokenRepository;

	@Autowired
	private TokenCleanupJob cleanupJob;

	@Autowired
	private UserRepository userRepository;

	@BeforeEach
	void setup() {
		refreshTokenRepository.deleteAll();
		verificationTokenRepository.deleteAll();
		userRepository.deleteAll();
	}

	@Test
	void shouldDeleteExpiredRefreshTokens() {
		User user = TestUserFactory.randomRegularUser();
		userRepository.save(user);

		// Expired token (yesterday)
		RefreshToken expired = new RefreshToken();
		expired.setToken("expired123");
		expired.setExpiryDate(Instant.now().minus(Duration.ofDays(1)));
		expired.setUser(user);

		// Valid token (tomorrow)
		RefreshToken valid = new RefreshToken();
		valid.setToken("valid123");
		valid.setExpiryDate(Instant.now().plus(Duration.ofDays(1)));
		valid.setUser(user);

		refreshTokenRepository.saveAll(List.of(expired, valid));

		// Run cleanup job
		cleanupJob.cleanExpiredRefreshTokens();

		List<RefreshToken> remaining = refreshTokenRepository.findAll();
		assertEquals(1, remaining.size());
		assertEquals("valid123", remaining.getFirst().getToken());
	}

	@Test
	void shouldDeleteExpiredVerificationTokens() {
		User user1 = userRepository.save(TestUserFactory.randomRegularUser());
		User user2 = userRepository.save(TestUserFactory.randomRegularUser());

		VerificationToken expired = new VerificationToken();
		expired.setToken("expired123");
		expired.setExpiryDate(Instant.now().minus(Duration.ofDays(1)));
		expired.setUser(user1);

		VerificationToken valid = new VerificationToken();
		valid.setToken("valid123");
		valid.setExpiryDate(Instant.now().plus(Duration.ofDays(1)));
		valid.setUser(user2);

		verificationTokenRepository.saveAll(List.of(expired, valid));

		// Run cleanup job
		cleanupJob.cleanExpiredVerificationTokens();

		List<VerificationToken> remaining = verificationTokenRepository.findAll();
		assertEquals(1, remaining.size());
		assertEquals("valid123", remaining.getFirst().getToken());
	}
}