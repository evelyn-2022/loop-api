package com.loop.api.modules.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.loop.api.common.constants.ApiRoutes;
import com.loop.api.common.exception.UserNotFoundException;
import com.loop.api.modules.user.dto.UpdateUserProfileRequest;
import com.loop.api.modules.user.dto.UserResponse;
import com.loop.api.modules.user.model.User;
import com.loop.api.modules.user.service.UserService;
import com.loop.api.security.UserPrincipal;
import com.loop.api.testutils.TestUserFactory;
import com.loop.api.testutils.TestUserResponseFactory;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Tag("UnitTest")
@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
public class UserControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private UserService userService;

	@Autowired
	private ObjectMapper objectMapper;

	private User user;
	private UserResponse userResponse;
	private UserPrincipal userPrincipal;

	@BeforeEach
	void setUp() {
		user = TestUserFactory.regularUser(1L);
		userResponse = TestUserResponseFactory.fromUser(user);
		userPrincipal = new UserPrincipal(user);
	}

	@AfterEach
	void tearDown() {
		SecurityContextHolder.clearContext();
	}

	private RequestPostProcessor authenticated(UserPrincipal principal) {
		Authentication auth = new UsernamePasswordAuthenticationToken(
				principal, null, principal.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(auth);
		return SecurityMockMvcRequestPostProcessors.authentication(auth);
	}

	@Nested
	@DisplayName("Tests for get my profile")
	class GetMyProfileTests {

		@Test
		@DisplayName("Should return 200 and user profile when authenticated")
		void shouldReturnUserProfileWhenAuthenticated() throws Exception {
			when(userService.getUserById(user.getId())).thenReturn(userResponse);

			mockMvc.perform(get(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal)))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("User profile fetched"))
					.andExpect(jsonPath("$.data.id").value(user.getId()))
					.andExpect(jsonPath("$.data.email").value(user.getEmail()))
					.andExpect(jsonPath("$.data.mobile").value(user.getMobile()))
					.andExpect(jsonPath("$.data.username").value(user.getUsername()))
					.andExpect(jsonPath("$.data.admin").value(user.isAdmin()))
					.andExpect(jsonPath("$.data.profileUrl").value(user.getProfileUrl()));
		}

		@Test
		@DisplayName("Should return 404 if user not found")
		void shouldReturnNotFoundWhenUserDoesNotExist() throws Exception {
			when(userService.getUserById(user.getId()))
					.thenThrow(new UserNotFoundException("User not found with id: " + user.getId()));

			mockMvc.perform(get(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal)))
					.andExpect(status().isNotFound())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(404))
					.andExpect(jsonPath("$.message").value("User not found with id: " + user.getId()));
		}
	}

	@Nested
	@DisplayName("Tests for update my profile")
	class UpdateMyProfileTests {

		@Test
		@DisplayName("Should return 200 and updated profile when valid request is made")
		void shouldUpdateProfileSuccessfully() throws Exception {
			UpdateUserProfileRequest request = new UpdateUserProfileRequest();
			request.setEmail("updated@example.com");

			userResponse.setEmail(request.getEmail());

			when(userService.updateUserProfile(eq(user.getId()), any())).thenReturn(userResponse);

			mockMvc.perform(put(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal))
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.data.email").value(request.getEmail()));
		}

		@Test
		@DisplayName("Should return 404 if user not found")
		void shouldReturnNotFoundIfUserDoesNotExist() throws Exception {
			UpdateUserProfileRequest request = new UpdateUserProfileRequest();
			request.setUsername("updatedUser");

			when(userService.updateUserProfile(eq(user.getId()), any()))
					.thenThrow(new UserNotFoundException("User not found with id: " + user.getId()));

			mockMvc.perform(put(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal))
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(request)))
					.andExpect(status().isNotFound())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(404))
					.andExpect(jsonPath("$.message").value("User not found with id: " + user.getId()));
		}

		@Test
		@DisplayName("Should return 400 with invalid fields")
		void shouldReturnBadRequestOnValidationFailure() throws Exception {
			UpdateUserProfileRequest badRequest = new UpdateUserProfileRequest();
			badRequest.setEmail("invalid-email");
			badRequest.setUsername("a@!");
			badRequest.setMobile("123abc");
			badRequest.setProfileUrl("not-a-url");

			mockMvc.perform(put(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal))
							.contentType(MediaType.APPLICATION_JSON)
							.content(objectMapper.writeValueAsString(badRequest)))
					.andExpect(status().isBadRequest())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(400))
					.andExpect(jsonPath("$.message").value("Validation failed"))
					.andExpect(jsonPath("$.data.email").value("Email format is invalid"))
					.andExpect(jsonPath("$.data.username").value("Username can only contain letters, numbers and " +
							"underscores"))
					.andExpect(jsonPath("$.data.mobile").value("Mobile number is not valid"))
					.andExpect(jsonPath("$.data.profileUrl").value("Profile URL must be a valid URL"));
		}
	}

	@Nested
	@DisplayName("Tests for delete my profile")
	class DeleteMyAccountTests {

		@Test
		@DisplayName("Should delete user and return 200 when authenticated")
		void shouldDeleteUserSuccessfully() throws Exception {
			doNothing().when(userService).deleteUser(user.getId());

			mockMvc.perform(delete(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal)))
					.andExpect(status().isOk())
					.andExpect(jsonPath("$.status").value("SUCCESS"))
					.andExpect(jsonPath("$.code").value(200))
					.andExpect(jsonPath("$.message").value("User deleted successfully"))
					.andExpect(jsonPath("$.data").doesNotExist());
		}

		@Test
		@DisplayName("Should return 404 if user does not exist")
		void shouldReturnNotFoundIfUserNotFound() throws Exception {
			doThrow(new UserNotFoundException("User not found with id: " + user.getId()))
					.when(userService).deleteUser(user.getId());

			mockMvc.perform(delete(ApiRoutes.User.ME)
							.with(authenticated(userPrincipal)))
					.andExpect(status().isNotFound())
					.andExpect(jsonPath("$.status").value("ERROR"))
					.andExpect(jsonPath("$.code").value(404))
					.andExpect(jsonPath("$.message").value("User not found with id: " + user.getId()));
		}
	}
}