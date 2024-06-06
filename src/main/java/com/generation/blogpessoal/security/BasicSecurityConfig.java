package com.generation.blogpessoal.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
 * objetivo da classe 
 * informar as configurações de segurança
 * liberar os links que não necessita de login
 */
@Configuration //é para informar que essa classe é uma classe de configuração
@EnableWebSecurity //é para informar que essas configurações se aplicacão a todo o projeto
public class BasicSecurityConfig {

	//injeção de dependencias que trazer o jwtAuthFilter
	@Autowired
    private JwtAuthFilter authFilter;

	//permite confirmar usuário e senha no banco de dados, vai ser aplicado na authenticationProvider
    @Bean
    UserDetailsService userDetailsService() {

        return new UserDetailsServiceImpl();
    }

    //criptografia da senha vamos aplicar no usuário para criptografia de senha
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //conseguiu validar usuario e senha valida no banco de dados essas informações
    @Bean
    AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    //implementar gerenciamento de autenticação
    //verifica se o usuário esta hapto ou não a acessar a api
    
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    /*
     * substitui a configuração do spring padrão de segurança pelas nossas configurações
     */
    
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	//configurações de politicas da sessão incluindo politica de cors que foi definida nas controllers que deve ser respeitada
    	/*
    	 * um dos ajustes feitos aqui no Stateless é para garantir que as sessões do usuário não fiquem
    	 * armazenadas
    	 * em crf.disable estamos desabilitando a proteção da security contra ataques de CSRF(intercepção de dados de autenticação antes de chegar no servidor)
    	 */
    	http
	        .sessionManagement(management -> management
	                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        		.csrf(csrf -> csrf.disable())
	        		.cors(withDefaults());
    	//************************atenção a esta parte *******************
    	/*
    	 * aqui vamos indicar quais as rotas vamos deixar abertas para acesso sem login/token
    	 * estamos passando tbm o método http OPTIONS que permite o usuário do api
    	 * ver quais opções são permitida ou obrigatórios para o cabeçalho da requisição
    	 * em .anyRequest().authenticated()) estamos fechando o acesso de todos os endpoints não informados (precisa estar logado)
    	 */
    	http
	        .authorizeHttpRequests((auth) -> auth
	                .requestMatchers("/usuarios/logar").permitAll()
	                .requestMatchers("/usuarios/cadastrar").permitAll()
	                .requestMatchers("/error/**").permitAll()
	                .requestMatchers(HttpMethod.OPTIONS).permitAll()
	                .anyRequest().authenticated())
	        .authenticationProvider(authenticationProvider())
	        .addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
	        .httpBasic(withDefaults());

    	//estamos aplicando a configuração acima "Contruindo" a solução.
		return http.build();

    }
}