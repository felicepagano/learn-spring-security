package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class LssSecurityConfig extends WebSecurityConfigurerAdapter {
	// WebSecurityConfigurerAdapter provide a good default configuration for the security
	// to change the configuration you must override the methods
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { // @// @formatter:off
		
		auth
		.inMemoryAuthentication()
		.withUser("user").password("pass")
		.roles("USER");
		
	} // @formatter:on
}
