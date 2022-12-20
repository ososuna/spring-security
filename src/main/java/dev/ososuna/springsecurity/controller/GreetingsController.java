package dev.ososuna.springsecurity.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/greetings")
public class GreetingsController {
  
  @GetMapping
  public ResponseEntity<String> sayHello() {
    return ResponseEntity.ok("Hello World from our API!");
  }

  @GetMapping("/goodbye")
  public ResponseEntity<String> sayGoodbye() {
    return ResponseEntity.ok("Goodbye World from our API!");
  }

}
