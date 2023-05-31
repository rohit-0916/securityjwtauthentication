package com.rohit.springjwt.controllers;

import java.util.*;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.rohit.springjwt.payload.request.ForgetPasswordRequest;
import com.rohit.springjwt.payload.request.ResetPasswordRequest;
import com.rohit.springjwt.security.services.MailSender;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rohit.springjwt.models.ERole;
import com.rohit.springjwt.models.Role;
import com.rohit.springjwt.models.User;
import com.rohit.springjwt.payload.request.LoginRequest;
import com.rohit.springjwt.payload.request.SignupRequest;
import com.rohit.springjwt.payload.response.JwtResponse;
import com.rohit.springjwt.payload.response.MessageResponse;
import com.rohit.springjwt.repository.RoleRepository;
import com.rohit.springjwt.repository.UserRepository;
import com.rohit.springjwt.security.jwt.JwtUtils;
import com.rohit.springjwt.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @Autowired
  private final MailSender mailSender;

  public AuthController(MailSender mailSender) {
    this.mailSender = mailSender;
  }

  @PostMapping("/login")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();    
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, 
                         userDetails.getId(), 
                         userDetails.getUsername(), 
                         userDetails.getEmail(), 
                         roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity
          .badRequest()
          .body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(), 
               signUpRequest.getEmail(),
               encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(adminRole);

          break;
        case "mod":
          Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(modRole);

          break;
        default:
          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @PostMapping("/forgotpassword")
  public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgetPasswordRequest request){
    String email = request.getEmail();
    User user = userRepository.findByEmail(email);
    if (user == null) {
      return ResponseEntity
              .badRequest()
              .body(new MessageResponse("Error: Email does not exist."));
    }
    String resetToken = UUID.randomUUID().toString();

    user.setResetToken(resetToken);
    userRepository.save(user);
    sendPasswordResetEmail(user.getEmail(), resetToken);

    return ResponseEntity.ok(new MessageResponse("Password reset email has been sent."));

  }

  @PostMapping("/reset-password")
  public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
    String resetToken = resetPasswordRequest.getResetToken();
    String newPassword = resetPasswordRequest.getNewPassword();

    User user = userRepository.findByResetToken(resetToken);

    if (user == null) {
      return ResponseEntity
              .badRequest()
              .body(new MessageResponse("Error: Invalid reset token."));
    }

    user.setPassword(encoder.encode(newPassword));
    user.setResetToken(null);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("Password reset successful."));
  }
  private void sendPasswordResetEmail(String recipientEmail, String resetToken) {
    String subject = "Password Reset";
    String content = "Dear User,\n\n"
            + "Your password reset token is: " + resetToken + "\n\n"
            + "If you didn't request a password reset, please ignore this email.\n\n"
            + "Best regards,\n"
            + "Your App Team";

    mailSender.sendEmail(recipientEmail, subject, content);
  }

}
