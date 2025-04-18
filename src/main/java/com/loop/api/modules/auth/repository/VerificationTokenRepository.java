package com.loop.api.modules.auth.repository;

import com.loop.api.modules.auth.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
	Optional<VerificationToken> findByToken(String token);

	@Transactional
	void deleteAllByExpiryDateBefore(Instant expiryDate);
}
