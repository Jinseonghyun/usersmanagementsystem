package jin.usersmanagementsystem.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jin.usersmanagementsystem.service.JWTUtils;
import jin.usersmanagementsystem.service.OurUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthFilter extends OncePerRequestFilter { //  각 요청 당 한 번씩 필터가 실행됩니다. JWT를 기반으로 인증을 처리하기 위해 OncePerRequestFilter 사용

    /**
     * 요청이 처리될 때마다 한 번씩 실행되는 필터로, 사용자의 JWT를 확인하고 검증하는 역할
     */
    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private OurUserDetailsService ourUserDetailsService;


    /**
     * JWT 추출 및 검증: doFilterInternal 메서드에서는 주로 요청 헤더에서 JWT를 추출하고, 그 토큰을 검증하는 작업을 수행
     * HttpServletRequest request: 클라이언트로부터 들어온 HTTP 요청을 나타냅니다. 이 요청에서 JWT를 추출
     * HttpServletResponse response: 서버에서 클라이언트로 보내는 HTTP 응답
     * FilterChain filterChain: 현재 필터에서 다음 필터로 요청을 전달하기 위해 사용
     * throws ServletException, IOException: 필터링 중 발생할 수 있는 예외를 처리
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        /**
         *  JWT 추출 및 검증
         *  authHeader = request.getHeader("Authorization"): HTTP 요청의 "Authorization" 헤더에서 JWT를 추출
         *  만약 헤더가 비어 있거나 null이라면, 필터 체인을 통해 요청을 다음 단계로 전달하고 메서드를 종료
         */
        final String authHeader = request.getHeader("Authorization"); // 헤더에서 토큰을 추출하여 헤더로 저장함 -> Authorization 인증이 된다.
        final String jwtToken;
        final String userEmail; // 사용자 이름으로 사용

        if (authHeader == null || authHeader.isBlank()) {
            filterChain.doFilter(request, response); // authHeader 이 비어 있거나 null 값이면 요청과 응답을 전달
            return;
        }


        jwtToken = authHeader.substring(7);         // "Authorization" 헤더에서 "Bearer "라는 접두사(7자)를 제외한 실제 JWT를 추출
        userEmail = jwtUtils.extractUsername(jwtToken);       // 추출한 JWT에서 사용자 이메일(또는 사용자 이름)을 가져옵니다. 이 이메일은 JWT에 포함된 클레임(Claims)에서 가져옵니다.

        /**
         * 사용자 인증 및 Spring Security 컨텍스트 설정
         * 사용자 이메일이 유효하고, 현재 SecurityContext에 인증 정보가 없는 경우에만 인증 절차를 진행
         */
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = ourUserDetailsService.loadUserByUsername(userEmail); // 이메일을 사용하여 UserDetails 객체를 로드(객체는 사용자에 대한 권한, 비밀번호 등의 정보를 포함)

            if (jwtUtils.isTokenValid(jwtToken, userDetails)) {  // JWT가 유효한지 확인합니다. 유효하다면, 아래의 코드를 통해 사용자 인증을 진행
                SecurityContext securityContext = SecurityContextHolder.getContext();
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()                     // UserDetails를 사용하여 인증 토큰을 생성
                );
                token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));         // 인증 토큰에 추가적인 요청 정보를 설정
                securityContext.setAuthentication(token);
                SecurityContextHolder.setContext(securityContext);                                    // SecurityContext에 인증된 사용자 정보를 설정
            }
        }
        // 청을 다음 필터로 전달하여 나머지 필터링 또는 요청 처리가 계속되도록 합니다. JWT가 검증되었고, SecurityContext에 설정되었기 때문에 이후의 요청은 인증된 사용자로 처리
        filterChain.doFilter(request, response);
    }
}
