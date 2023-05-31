package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;


public class CustomAuthenticationProvider implements AuthenticationProvider {


    private UserDetailsService userDetailsService;

    private PasswordEncoder passwordEncoder;

    @Override // 파라미터로 전달받는 인증객체는 AuthenticationManager로부터 전달받는 인증객체임
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        //userDetailsService로 부터 userDetail type의 객체를 얻어옴. AccountContext로 변환해서
        //but customUserDetailService의 loadUserByUsername 메서드를 통과하지 못하면 null이 반환되기 때문에 ID를 검증하지 못해 Fail
        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

        // 비밀번호가 맞는지 검증
        if(!passwordEncoder.matches(password, accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialException");
        }// 통과하면 Passwd 검증성공

        // ID-PW 검증 통과하면 토큰생성함. 파라미터로 사용자객체, 비밀번호, 인증객체 사용
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());

        return authenticationToken;
    }

    @Override // 파라미터로 전달된 클래스의 타입이 일치할 때 해당 클래스가 인증을 처리하도록 토큰을 부여
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
