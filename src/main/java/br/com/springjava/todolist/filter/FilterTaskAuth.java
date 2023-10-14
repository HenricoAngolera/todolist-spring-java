package br.com.springjava.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.springjava.todolist.user.IUserRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var servletPath = request.getServletPath();

    if (servletPath.startsWith("/tasks/")) {
      // pegar a autenticação (usuario, senha)
      var authorization = request.getHeader("Authorization");

      // separar autorização decodificada
      var authEncoded = authorization.substring("Basic".length()).trim();

      // decodificar e transformar em array de bytes
      byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

      // passar a autorização de um array de bytes para string
      var authString = new String(authDecoded);

      // Separar string dividindo ela em um array de duas posições
      String[] credentials = authString.split(":");

      // para pegar username e senha de array
      String username = credentials[0];
      String password = credentials[1];

      // validar usuario
      var user = this.userRepository.findByUsername(username);
      if (user == null) {
        response.sendError(401);
      } else {
        // validar senha
        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
        if (passwordVerify.verified) {
          // segue viagem
          request.setAttribute("idUser", user.getId());
          filterChain.doFilter(request, response);
        } else {
          response.sendError(401);
        }
      }
    } else {
      filterChain.doFilter(request, response);
    }

  }

}
