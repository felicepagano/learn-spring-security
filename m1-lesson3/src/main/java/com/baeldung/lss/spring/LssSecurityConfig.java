package com.baeldung.lss.spring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class LssSecurityConfig extends WebSecurityConfigurerAdapter {
	
	public LssSecurityConfig() {
        super();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception { // @formatter:off 
        auth.
            inMemoryAuthentication().
            withUser("pippo").password("pluto").roles("USER");
    } // @formatter:on

	@Override
	protected void configure(HttpSecurity http) throws Exception { // @formatter:off
		http
		// authorization of the URL 
		.authorizeRequests()
			// with hasRole API your principle must have the ROLE_ADMIN role. this because spring automatically prefixed with ROLE_.
			// To avoid prefix you must use hasAutority API .antMatchers("/delete/**").hasAutority("ADMIN"). with any you will be able to use more than one role.
			.antMatchers("/delete/*").denyAll()
			// .antMatchers("/delete/**").hasAnyAuthority("ADMIN", "ADMIN2")
			// .antMatchers("/admin").hasIpAddress(ipaddressExpression)
			// every request must be authenticated
			.anyRequest().authenticated()
			.and()
		.formLogin();
	} // @formatter:on 
    
}
