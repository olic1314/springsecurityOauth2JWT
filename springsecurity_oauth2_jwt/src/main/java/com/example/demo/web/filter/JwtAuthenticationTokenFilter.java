//package com.example.demo.web.filter;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import javax.servlet.FilterChain;
//import javax.servlet.ServletException;
//import javax.servlet.http.HttpServletRequest;
//import javax.servlet.http.HttpServletResponse;
//import java.io.IOException;
//
///**
// * @author olic
// * @date 2023/6/1019:44
// */
//@Component
//public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//            throws ServletException, IOException {
//
////        LoginUser loginUser = tokenService.getLoginUser(request);
//        /**
//         * 在页面中输入用户名和密码之后首先会进入到UsernamePasswordAuthenticationToken验证(Authentication)，
//         * 然后生成的Authentication会被交由AuthenticationManager来进行管理
//         * 而AuthenticationManager管理一系列的AuthenticationProvider，
//         * 而每一个Provider都会通UserDetailsService和UserDetail来返回一个
//         * 以UsernamePasswordAuthenticationToken实现的带用户名和密码以及权限的Authentication
//         */
//        UserDetails user = User.withUsername("admin").password(passwordEncoder.encode("123456")).authorities("p1").build();
//
//        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user, null);
//        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//
//        chain.doFilter(request, response);
//    }
//}
