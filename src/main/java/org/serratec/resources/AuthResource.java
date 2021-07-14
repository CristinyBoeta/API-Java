package org.serratec.resources;

import java.util.Optional;

import org.serratec.dto.LoginDTO;
import org.serratec.dto.TokenDTO;
import org.serratec.models.Cliente;
import org.serratec.repository.ClienteRepository;
import org.serratec.security.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;

@RestController
@Api(value = "API - Autenticacao")
public class AuthResource {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private TokenService tokenService;
	
	@Autowired
	private ClienteRepository clienteRepository;
	
	@ApiOperation(value = "Geracao do token de autenticacao a partir de username e senha")
	@PostMapping("/auth")
	public ResponseEntity<?> auth(@RequestBody @Validated LoginDTO loginDTO){
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginDTO.getUser(), loginDTO.getPass());
		
		Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
		
		String token = tokenService.generateToken(authentication);		
		
		TokenDTO tokenDTO = new TokenDTO();
		tokenDTO.setToken(token);
		tokenDTO.setType("Bearer");
		tokenDTO.setEmail(loginDTO.getUser());
		
		Optional<Cliente> optional = clienteRepository.findByEmail(loginDTO.getUser());

		if (optional.isPresent()) {
			tokenDTO.setId(optional.get().getId());
		}
		
		return new ResponseEntity<>(tokenDTO, HttpStatus.OK);		
	}

}
