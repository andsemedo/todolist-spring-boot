package cv.com.andersonsemedo.todolist.Filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import cv.com.andersonsemedo.todolist.user.IUserRepository;
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

        var serveletPath = request.getServletPath();

        if(serveletPath.startsWith("/tasks/")) {

            //pegar a autenticação (username e password)
            var authorization = request.getHeader("Authorization");
            System.out.println("Authorization");
            System.out.println(authorization);

            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

            var authString = new String(authDecoded);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            //validar utilizador
            var user = this.userRepository.findByUsername(username);
            if(user == null ) {
                response.sendError(401, "Utilizador sem autorização");
            } else {
                //validar password
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if(passwordVerify.verified) {

                    request.setAttribute("userId", user.getId());

                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
                
            }


            //validar password
        } else {
            filterChain.doFilter(request, response);
        }

        
        
    }

    
}
