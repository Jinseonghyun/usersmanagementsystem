package jin.usersmanagementsystem.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * CORS(Cross-Origin Resource Sharing) 설정을 구성하기 위한 클래스입니다.
 * CORS는 웹 애플리케이션이 다른 도메인에서 리소스에 접근할 수 있도록 허용하는 메커니즘으로,
 * 보안상의 이유로 기본적으로 브라우저에서는 다른 도메인 간의 리소스 접근을 제한합니다.
 * 이 설정을 통해 CORS 규칙을 정의하고, 애플리케이션에서 다양한 클라이언트 도메인들이 접근할 수 있도록 설정
 */

@Configuration  // 의 @Bean 메서드를 정의하고, Spring 컨테이너에서 관리되는 설정 클래스
public class CorsConfig {

    @Bean // 자동으로 공개되도록
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {

            @Override
            public void addCorsMappings(CorsRegistry registry) {  // CORS 매핑을 추가하는 역할을 합니다. CorsRegistry를 사용하여 특정 경로에 대한 CORS 규칙을 정의
                registry.addMapping("/**")             // 애플리케이션의 모든 경로("/**")에 대해 CORS를 적용하도록 설정합니다. 이 의미는 애플리케이션의 모든 URL 경로에 대해 CORS 규칙이 적용
                        .allowedMethods("GET", "POST", "PUT", "DELETE") //  CORS 규칙에 따라 허용할 HTTP 메서드를 지정합니다. 이 설정에서는 GET, POST, PUT, DELETE 메서드가 허용
                        .allowedOrigins("*");  //  모든 도메인("*")에서 오는 요청을 허용합니다. 즉, 어떤 도메인에서든 애플리케이션의 리소스에 접근 가능
            }
        };
    }
}
