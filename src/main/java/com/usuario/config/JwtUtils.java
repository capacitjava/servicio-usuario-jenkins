package com.usuario.config;

import java.security.Key;
import java.util.Date;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

/*
 * QUE ES UN TOKEN?
 * 
 * CICLO DE VIDA DE UN TOKEN? CREDENCIAL, INFORMACIÓN,
 * 
 * DONDE GUARDAS LOS TOKENS?
 * 
 * PUEDES GUARDAR UN TOKEN EN MEMORIA?
 * 
 * QUE ES UN KEY EN JAVA?
 * 
 */

@Component
public class JwtUtils {
	
	//CLAVE SECRETA DE 32 CARACTERES - 256 BITS
	private static final String SECRET_KEY = "$2a$16$UlCKMbna3AFeagx5uR9ar.bm2Ay78HiK.1eNqsyg3SDh4LwVDugAW";
	
	//TIEMPO DE EXPIRACIÓN DE 1 HORA EN MILISEGUNDOS
	private static final long EXPIRATION_TIME = 3600000;
	
	private final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
	
	//GENERA TOKEN - JWT JSON WEB TOKEN
	public String generarToken(String username, String role) {
		return Jwts
				.builder()
				.setSubject(username)
				.claim("role", role)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(key, SignatureAlgorithm.HS256)
				.compact();
	}
}













