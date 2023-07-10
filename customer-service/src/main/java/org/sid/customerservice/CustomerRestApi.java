package org.sid.customerservice;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class CustomerRestApi {
    @GetMapping("/customer")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public Map<String,Object> customer(Authentication authentication){
        return Map.of("name","Mohamed","email","Mohamed@Gmail.com",
        "username :",authentication.getName(),
        "scope :" ,authentication.getAuthorities());
    }
}
