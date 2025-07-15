package com;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	@Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer auth2AuthorizationServerConfigurer 
		= OAuth2AuthorizationServerConfigurer.authorizationServer();
		
		auth2AuthorizationServerConfigurer.oidc(Customizer.withDefaults());
        http
		        .securityMatcher(auth2AuthorizationServerConfigurer.getEndpointsMatcher())
		        .with(auth2AuthorizationServerConfigurer, Customizer.withDefaults())
		            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
		            .exceptionHandling(ex -> 
		            ex.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"),
		            		new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
		            .csrf(csrf -> csrf.ignoringRequestMatchers(auth2AuthorizationServerConfigurer.getEndpointsMatcher()));
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
//            .clientId("custom-client")
//            .clientSecret("{noop}secret")
//            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//            .redirectUri("http://localhost:8084/login/oauth2/code/custom-client")
//            .scope("openid")
//            .scope("profile")
//            .build();
//
//        return new InMemoryRegisteredClientRepository(client);
//    }
    
//    @Bean
//	public UserDetailsService userDetailsService() {
//	    UserDetails user = User.builder()
//	        .username("test")
//	        .password("{noop}test")
//	        .roles("USER")
//	        .build();
//
//	    return new InMemoryUserDetailsManager(user);
//	}
//
//    @Bean
//    public OAuth2AuthorizationService authorizationService(RegisteredClientRepository clients) {
//        return new InMemoryOAuth2AuthorizationService();
//    }
}