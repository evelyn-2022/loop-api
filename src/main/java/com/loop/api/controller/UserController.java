package com.loop.api.controller;

import com.loop.api.dto.UpdateUserProfileRequest;
import com.loop.api.dto.UserResponse;
import com.loop.api.model.User;
import com.loop.api.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    // Get my profile
    @GetMapping("/{id}")
    @PreAuthorize("#id == principal.getId()")
    public ResponseEntity<UserResponse> getUserById(@PathVariable Long id) {
        UserResponse user = userService.getUserById(id);
        return ResponseEntity.ok(user);
    }

    // Update my profile
    @PutMapping("/{id}")
    @PreAuthorize("#id == principal.getId()")
    public ResponseEntity<User> updateUserProfile(@PathVariable Long id,
                                                  @RequestBody UpdateUserProfileRequest profileRequest) {
        User updatedUser = userService.updateUserProfile(id, profileRequest);
        return ResponseEntity.ok(updatedUser);
    }

    // Delete my account
    @DeleteMapping("/{id}")
    @PreAuthorize("#id == principal.getId()")
    public ResponseEntity<String> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.ok("User deleted successfully");
    }
}
