package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class LssSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { // @formatter:off 
        auth.
            inMemoryAuthentication().
            withUser("user").password("pass").roles("USER");
    } // @formatter:on

	@Override
	protected void configure(HttpSecurity http) throws Exception { // @formatter:off
		http
		// authorization of the URL 
		// every requests need to be authenticated
		.authorizeRequests()
			.anyRequest().authenticated()
			// with hasRole API your principle must have the ROLE_ADMIN role. this because spring automatically prefixed with ROLE_.
			// To avoid prefix you must use hasAutority API .antMatchers("/delete/**").hasAutority("ADMIN"). with any you will be able to use more than one role.
			.antMatchers("/delete/**").hasAuthority("ADMIN")
			// .antMatchers("/delete/**").hasAnyAuthority("ADMIN", "ADMIN2")
			// .antMatchers("/admin").hasIpAddress(ipaddressExpression)
			.and()
		.formLogin().and()
		.httpBasic();
	} // @formatter:on 
    
}
