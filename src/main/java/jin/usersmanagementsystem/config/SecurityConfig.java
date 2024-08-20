package jin.usersmanagementsystem.config;

import jin.usersmanagementsystem.service.OurUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity // 웹 보안 활성화 (Spring Security 필터 체인을 구성하고, 보안 설정을 적용할 수 있게 합니다.)
public class SecurityConfig {

    @Autowired
    private OurUserDetailsService ourUserDetailsService;
    @Autowired
    private JWTAuthFilter jwtAuthFilter;

    /**
     * request -> request.requestMatchers 경로로 들어오는 요청은 인증 없이 접근할 수 있도록 허용
     *
     */
    @Bean // SecurityFilterChain: Spring Security의 필터 체인을 정의합니다. 이 필터 체인은 보안 규칙을 설정하고, 모든 HTTP 요청에 적용
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable)                            // CSRF 보호를 비활성화합니다. JWT를 사용하는 경우 일반적으로 CSRF 보호가 필요하지 않습니다.
                .cors(Customizer.withDefaults())                                      // CORS는 다른 도메인에서의 리소스 접근을 제어
                .authorizeHttpRequests(request -> request.requestMatchers("/auth/**", "/public/**").permitAll()   // authorizeHttpRequests:  HTTP 요청에 대한 인증 및 권한 부여 규칙을 설정
                        .requestMatchers("/admin/**").hasAnyAuthority("ADMIN")                           // ADMIN 권한을 가진 사용자만 접근할 수 있도록 제한
                        .requestMatchers("/user/**").hasAnyAuthority("USER")                             //  USER 권한을 가진 사용자만 접근할 수 있도록 제한
                        .requestMatchers("/adminuser/**").hasAnyAuthority("ADMIN", "USER")               // ADMIN 또는 USER 권한을 가진 사용자만 접근 허용
                        .anyRequest().authenticated())                                                                //  위의 경로에 해당하지 않는 모든 요청은 인증된 사용자만 접근할 수 있도록 합니다.
                .sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider()).addFilterBefore(
                        jwtAuthFilter, UsernamePasswordAuthenticationFilter.class
                );
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(ourUserDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
