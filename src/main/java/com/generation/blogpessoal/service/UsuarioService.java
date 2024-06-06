package com.generation.blogpessoal.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.generation.blogpessoal.model.Usuario;
import com.generation.blogpessoal.model.UsuarioLogin;
import com.generation.blogpessoal.repository.UsuarioRepository;
import com.generation.blogpessoal.security.JwtService;

@Service // Aqui estamos tratando as regras de negócio
public class UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private JwtService jwtService;


    
    @Autowired
    private AuthenticationManager authenticationManager;

    // Regra de negócio: permitir o cadastro de um usuário
    public Optional<Usuario> cadastrarUsuario(Usuario usuario) {
        // Verifica se já existe um usuário com o mesmo nome de usuário (email)
        if (usuarioRepository.findByUsuario(usuario.getUsuario()).isPresent())
            return Optional.empty();

        // Criptografa a senha antes de salvar no banco de dados
        usuario.setSenha(criptografarSenha(usuario.getSenha()));

        return Optional.of(usuarioRepository.save(usuario));
    }

    // Método para criptografar a senha usando BCryptPasswordEncoder    
    private String criptografarSenha(String senha) {
		//Classe que trata a criptografia
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder.encode(senha);//método encoder sendo aplicado na senha
	}

    // Regra de negócio: atualizar um usuário
    public Optional<Usuario> atualizarUsuario(Usuario usuario) {
        // Verifica se o usuário existe no banco de dados
        if (usuarioRepository.findById(usuario.getId()).isPresent()) {

            // Verifica se já existe outro usuário com o mesmo nome de usuário (email)
            Optional<Usuario> buscarUsuario = usuarioRepository.findByUsuario(usuario.getUsuario());
            if (buscarUsuario.isPresent() && !buscarUsuario.get().getId().equals(usuario.getId()))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Usuário já existe");

            // Criptografa a senha antes de salvar as alterações no banco de dados
            usuario.setSenha(criptografarSenha(usuario.getSenha()));
            return Optional.ofNullable(usuarioRepository.save(usuario));

        } else {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Usuário não encontrado");
        }
    }

    public Optional<UsuarioLogin> autenticarUsuario(Optional<UsuarioLogin> usuarioLogin) {
        // Verifica se as credenciais de login estão presentes
        if (usuarioLogin.isPresent()) {
            // Cria um objeto com as credenciais de login
            var credenciais = new UsernamePasswordAuthenticationToken(usuarioLogin.get().getUsuario(),
                    usuarioLogin.get().getSenha());
            // Autentica o usuário
            Authentication authentication = authenticationManager.authenticate(credenciais);
            // Se a autenticação for bem-sucedida, gera o token JWT
            if (authentication.isAuthenticated()) {
                Optional<Usuario> usuario = usuarioRepository.findByUsuario(usuarioLogin.get().getUsuario());
                if (usuario.isPresent()) {
                    usuarioLogin.get().setNome(usuario.get().getNome());
                    usuarioLogin.get().setFoto(usuario.get().getFoto());
                    usuarioLogin.get().setToken(gerarToken(usuarioLogin.get().getUsuario()));
                    usuarioLogin.get().setSenha("");
                    return usuarioLogin;
                }
            }
        }
        return Optional.empty();
    }
    
    private String gerarToken(String usuario) {
        return "Bearer " + jwtService.generateToken(usuario);
    }
}
