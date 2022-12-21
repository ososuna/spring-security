package dev.ososuna.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.ososuna.springsecurity.dao.UserDao;
import dev.ososuna.springsecurity.model.AuthRequest;
import dev.ososuna.springsecurity.util.JwtUtil;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final UserDao userDao;
  private final JwtUtil jwtUtil;

  @PostMapping("/authenticate")
  public ResponseEntity<String> authenticate(@RequestBody AuthRequest request) {
    authenticationManager.authenticate(
      new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
    );
    final UserDetails user = userDao.findUserByEmail(request.getEmail());
    if (user != null) {
      return ResponseEntity.ok(jwtUtil.generateToken(user));
    }
    return ResponseEntity.status(400).body("Invalid credentials");
  }
}
