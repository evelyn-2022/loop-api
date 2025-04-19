package com.loop.api.common.constants;

public final class ApiRoutes {

	public static final String CONTEXT_PATH = "/api/v1";

	private ApiRoutes() {
	}

	public static final class Admin {
		public static final String BASE = "/admin";
		public static final String USERS = BASE + "/users";
	}

	public static final class Auth {
		public static final String BASE = "/auth";
		public static final String LOGIN = BASE + "/login";
		public static final String SIGNUP = BASE + "/signup";
		public static final String CHECK_EMAIL = BASE + "/check-email";
		public static final String VERIFY = BASE + "/verify";
		public static final String RESEND_VERIFICATION = BASE + "/resend-verification";
		public static final String REFRESH = BASE + "/refresh";
		public static final String LOGOUT = BASE + "/logout";
	}

	public static final class User {
		public static final String BASE = "/users";
		public static final String ME = BASE + "/me";
	}
}
