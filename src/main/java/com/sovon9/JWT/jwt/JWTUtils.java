package com.sovon9.JWT.jwt;

import java.security.Key;
import java.util.Date;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JWTUtils
{
	Logger LOGGER = LoggerFactory.getLogger(JWTUtils.class);
	@Value("${spring.app.jwtSecret}")
	private String jwtSecret;
	
	@Value("${spring.app.jwtExpiration}")
	private Long jwtExpiration;
	
	/**
	 * extracts the JWT token from header
	 * @param request
	 * @return
	 */
	public String getJwtTokenFromHeader(HttpServletRequest request)
	{
		String jwtToken=null;
		String bearerToken = request.getHeader("Authorization");
		LOGGER.info("bearerToken from header : "+bearerToken);
		// JWT Token is in the form "Bearer token". Remove Bearer word and get only the Token
		if (bearerToken != null && bearerToken.startsWith("Bearer "))
		{
			jwtToken = bearerToken.substring(7); // Remove Bearer prefix
		}
		return jwtToken;
	}
	
	/**
	 * for generation of JWT token from username
	 * @param userdetails
	 * @return
	 */
	public String generateToken(UserDetails userdetails) 
	{
		return Jwts.builder()
                .subject(userdetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(key())
                .compact();
	}

	/**
	 * get the secret key
	 * @return
	 */
	private Key key()
	{
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
	}

	/**
	 * validate the JWT token on basis of secret key
	 * @param authToken
	 * @return
	 */
	public boolean validateJWTToken(String authToken)
	{
		  try {
	            System.out.println("Validate");
	            //verifying with secrt key and parse it
	            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
	            return true;
	        } catch (MalformedJwtException e) {
	            LOGGER.error("Invalid JWT token: {}", e.getMessage());
	        } catch (ExpiredJwtException e) {
	            LOGGER.error("JWT token is expired: {}", e.getMessage());
	        } catch (UnsupportedJwtException e) {
	            LOGGER.error("JWT token is unsupported: {}", e.getMessage());
	        } catch (IllegalArgumentException e) {
	            LOGGER.error("JWT claims string is empty: {}", e.getMessage());
	        }
	        return false;
	}
	
	/**
	 * get userName from JWT Token
	 * @param token
	 * @return
	 */
	 public String getUserNameFromJwtToken(String token) {
	        return Jwts.parser()
	                        .verifyWith((SecretKey) key())
	                .build().parseSignedClaims(token)
	                .getPayload().getSubject();
	    }
	
}
