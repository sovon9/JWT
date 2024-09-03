package com.sovon9.JWT.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.sovon9.JWT.jwt.JwtRequestFilter;
import com.sovon9.JWT.service.MyUserDetailsService;


@EnableMethodSecurity
@EnableWebSecurity
@Configuration
public class SecurityConfig
{

	@Bean
    public JwtRequestFilter jwtRequestFilter() {
        return new JwtRequestFilter();
    }
	
	/**
	 * loading password from database by extending userdetails service class
	 * @param passwordEncoder
	 * @return
	 */
	@Bean
	public UserDetailsService userDetailsService()
	{
		return new MyUserDetailsService();
	}

	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/home").permitAll() // permitting all access without authentication
                .requestMatchers("/signin").permitAll() 
                .anyRequest().authenticated() // authenticating all other requests
            )
            .sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//            .formLogin(formLogin -> formLogin
//                .loginPage("/login")
//                .defaultSuccessUrl("/home")
//                .permitAll()
//            )
            //.formLogin(withDefaults())
            //.httpBasic(withDefaults())
            .csrf(csrf->csrf.disable())
            .logout(logout -> logout.permitAll())
            .addFilterBefore(jwtRequestFilter(),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
	
	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public AuthenticationProvider authenticationProvider()
	{
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setUserDetailsService(userDetailsService());
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
		return daoAuthenticationProvider;
	}
	
	 @Bean
	    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
	        return builder.getAuthenticationManager();
	    }
	
}
