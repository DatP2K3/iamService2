package com.evotek.iam.controller;

import com.evotek.iam.dto.request.AuthenticationRequestDTO;
import com.evotek.iam.dto.request.IntrospectRequestDTO;
import com.evotek.iam.dto.request.LogoutRequestDTO;
import com.evotek.iam.dto.request.RefreshRequestDTO;
import com.evotek.iam.dto.response.AuthenticationResponseDTO;
import com.evotek.iam.dto.response.IntrospectResponseDTO;
import com.evotek.iam.service.AuthService;
import com.nimbusds.jose.JOSEException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthService authService;

    @PostMapping("/token")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(@RequestBody AuthenticationRequestDTO request) {
        AuthenticationResponseDTO result = authService.authenticate(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/introspect")
    public ResponseEntity<IntrospectResponseDTO> authenticate(@RequestBody IntrospectRequestDTO request)
            throws ParseException, JOSEException {
        IntrospectResponseDTO result = authService.introspect(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponseDTO> authenticate(@RequestBody RefreshRequestDTO request)
            throws ParseException, JOSEException {
        AuthenticationResponseDTO result = authService.refreshToken(request);
        return ResponseEntity.ok(result);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequestDTO request)
            throws ParseException, JOSEException {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }
}
