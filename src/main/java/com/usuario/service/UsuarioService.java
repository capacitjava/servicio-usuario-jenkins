package com.usuario.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.usuario.config.JwtUtils;
import com.usuario.modelo.Usuario;
import com.usuario.repository.UsuarioRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UsuarioService {

	private final UsuarioRepository usuarioRepository;
	private final PasswordEncoder passwordEncoder;
	
	//PARA GENERAR TOKEN JWT
	private final JwtUtils jwtUtils;

	public Usuario registrarUsuario(Usuario usuario) {
		
		if (usuarioRepository.existsByUsername(usuario.getUsername())) {
			throw new ResponseStatusException(
					HttpStatus.CONFLICT,
					"❌ EL USUARIO '" + usuario.getUsername() +
					"' YA EXISTE EN SISTEMA"					
					);
		}
		
		//ENCRIPTA EL PASSWORD
		usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
		
		return usuarioRepository.save(usuario);
	}
	
	//PARA AUTENTICAR USUARIO Y PASSWORD
	public String autenticarUsuario(String username, String password) {
		
		//1.- BUSCAR SI EL USUARIO EXISTE EN LA BASE DE DATOS
		Usuario usuario = usuarioRepository.findByUsername(username)
				.orElseThrow(() -> new ResponseStatusException(
			 HttpStatus.UNAUTHORIZED, "❌ USUARIO O CONTRASEÑA INCORRECTOS"
						));
		
		//2.- VERIFICAR SI LA CONTRASEÑA ENCRIPTADA COINCIDE
		if (!passwordEncoder.matches(password, usuario.getPassword())) {
			throw new ResponseStatusException(
		    HttpStatus.UNAUTHORIZED, "❌ USUARIO O CONTRASEÑA INCORRECTOS"
			);
		}
		
		//GENERAR Y RETORNAR EL TOKEN SI ES CORRECTO....
		return jwtUtils.generarToken(usuario.getUsername(), usuario.getPassword());
	}
	
}

