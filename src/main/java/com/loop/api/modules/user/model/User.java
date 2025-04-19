package com.loop.api.modules.user.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Entity
@Getter
@Setter
@ToString(exclude = "password")
@Table(name = "users",
		indexes = {
				@Index(name = "idx_user_email", columnList = "email"),
				@Index(name = "idx_user_mobile", columnList = "mobile"),
				@Index(name = "idx_user_username", columnList = "username")
		}
)
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(nullable = false, unique = true)
	private String email;

	@Column(unique = true)
	private String mobile;

	@Column(nullable = false)
	private String password;

	@Column(nullable = false, unique = true)
	private String username;

	@Column(nullable = false)
	private boolean admin = false;

	@Column(nullable = false)
	private boolean verified = false;

	@Column
	private String profileUrl;
}
