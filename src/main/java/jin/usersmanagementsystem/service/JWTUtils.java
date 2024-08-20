package jin.usersmanagementsystem.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

@Component
public class JWTUtils {

    /**
     * JWTUtils
     * 로그인한 사용자에 대한 서명을 생성
     * 로그인한 사용자는 항상 서명을 가지고 다니고 보안 엔드포인트에 엑세스 하려고 할 때 마다 해당 서명이 인증되고 시스템이 진행된다.
     * 해당 사용자가 해당 항목에 엑세스 할 수 있도록 허용하는 것이 기본적인 서비스의 전부
     */

    private SecretKey Key; // 개인이 가지고 있을 JWT 서명 및 확인에 사용되는 키
    private static final long EXPIRATION_TIME = 86400000;  // 만료시간은 = 토큰 비밀 키의 지속 시간  (지금은 24시간을 원한다. // 24시간 (86400000L)) // 토큰 만료 시간을 정의

    // 생성자에서 Key 를 생성할 예정 -> secreteString 을 가져온다.
    // 생성자는 토큰 생성 및 확인에 사용되는 비밀 키를 초기화
    public JWTUtils(){ // 하드코딩된 base64 인코딩 문자열이 비밀 키로 제공
        String secreteString = "843567893696976453275974432697R634976R738467TR678T34865R6834R8763T478378637664538745673865783678548735687R3";
        byte[] keyBytes = Base64.getDecoder().decode(secreteString.getBytes(StandardCharsets.UTF_8)); // base64로 인코딩된 문자열을 바이트로 디코딩해서 utf8 용 표준 문자
        this.Key = new SecretKeySpec(keyBytes, "HmacSHA256"); // 새 비밀 키와 같다,  HMAC SHA-256 알고리즘을 지정하여 디코딩된 바이트에서 SecretKey를 생성
    }

    /**
     * 토큰을 생성
     */
    public String generateToken(UserDetails userDetails) {

        return Jwts.builder()  // JWT 빌드를 시작
                .subject(userDetails.getUsername())  // 토큰의 제목(일반적으로 사용자 이름)을 설정
                .issuedAt(new Date(System.currentTimeMillis()))   //  토큰 발급 시간을 설정
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))  // 토큰의 만료 시간을 발급 시간으로부터 24시간으로 설정
                .signWith(Key) // 비밀 키를 사용하여 토큰에 서명
                .compact(); //  JWT 생성 프로세스를 마무리하고 토큰을 문자열로 반환
    }

    /**
     * refreshToken 생성
     */
    public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails) {

        // 사용자 세부 정보를 claims 화
        return Jwts.builder()
                .claims(claims)  // 토큰에 맞춤 클레임(추가 데이터)을 포함
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Key)
                .compact(); // 생성된 후 compact
    }

    /**
     * 토큰에서 사용자 이름 추출 (JWT에서 사용자 이름(제목)을 추출)
     * 토큰의 클레임에서 주제를 추출하는 도우미 메서드를 호출
     * 비밀 키를 사용하여 JWT를 구문 분석하고 확인 (토큰의 페이로드(클레임)를 검색)
     */
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    // JWT에서 특정 클레임을 추출하는 일반적인 방법
    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction) {
        return claimsTFunction.apply(Jwts.parser().verifyWith(Key).build().parseSignedClaims(token).getPayload());
    }

    /**
     * 토큰 검증
     * 토큰의 사용자 이름을 제공된 UserDetails와 비교하여 토큰이 유효한지 확인하고 토큰이 만료되지 않았는지 확인
     */
    // 토큰이 유효한지 또는 토큰이 만료되므로 빨리 수행합니다.
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    /**
     * 토큰 만료 확인
     * JWT가 만료되었는지 확인
     * 토큰에서 만료 시간을 추출
     */
    public boolean isTokenExpired(String token) {
        return extractClaims(token, Claims::getExpiration).before(new Date()); // 현재 날짜와 비교하여 토큰이 만료되었는지 확인
    }
}
