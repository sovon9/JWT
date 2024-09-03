package com.sovon9.JWT.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtRequestFilter extends OncePerRequestFilter
{
	Logger LOGGER = LoggerFactory.getLogger(JwtRequestFilter.class);
	
	@Autowired
	private JWTUtils jwtUtils;
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException
	{
		try
		{
			String jwtToken = jwtUtils.getJwtTokenFromHeader(request);
			LOGGER.error("JWTToken : " + jwtToken);
			// start validation
			if(null!=jwtToken && jwtUtils.validateJWTToken(jwtToken))
			{
				String userName = jwtUtils.getUserNameFromJwtToken(jwtToken);
				//Check if the Username is Present and the User is Not Authenticated Yet
				if(null!=userName && SecurityContextHolder.getContext().getAuthentication() == null)
				{
					// getting UserDetails to form Authentication Token
					UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
					//signifies that the user is authenticated based on the token and has the necessary roles
					UsernamePasswordAuthenticationToken authenticationToken = 
							new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					// Setting authentication token in SecurityContext
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				}
			}
		}
		catch(Exception e)
		{
			LOGGER.error("Authentication Set Failed : "+e);
		}
		filterChain.doFilter(request, response);
	}

}
