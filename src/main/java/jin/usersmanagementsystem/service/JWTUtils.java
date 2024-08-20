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

    private SecretKey Key; // 개인이 가지고 있을 키
    private static final long EXPIRATION_TIME = 86400000;  // 만료시간은 = 토큰 비밀 키의 지속 시간  (지금은 24시간을 원한다. // 24시간 (86400000L))

    // 생성자에서 Key 를 생성할 예정 -> secreteString 을 가져온다.
    public JWTUtils(){
        String secreteString = "843567893696976453275974432697R634976R738467TR678T34865R6834R8763T478378637664538745673865783678548735687R3";
        byte[] keyBytes = Base64.getDecoder().decode(secreteString.getBytes(StandardCharsets.UTF_8)); // 디코딩을 해서 utf8 용 표준 문자 세트로 만들거야
        this.Key = new SecretKeySpec(keyBytes, "HmacSHA256"); // 새 비밀 키와 같다,  비밀 키 사양은 키 바이트를 전달하고 보안을 위해 이 키를 해싱하고 생성
    }

    //토큰을 새로 고치기 위한 토큰을 생성해주는 모드를 생성
    public String generateToken(UserDetails userDetails) {

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Key)
                .compact(); // 생성된 후 compact
    }

    // refreshToken 생성하려는 겅우 해당 문자열을 다시 생성
    public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails) {

        // 사용자 세부 정보를 claims 화
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Key)
                .compact(); // 생성된 후 compact
    }

    // 토큰을 검증하는데 사용
    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject) //  주제에 대한 패스 여기에서 추출을 생성
    }

    private <T> T extractClaims(String token, Function<Claims, T> claimsTFunction) {
        return claimsTFunction.apply(Jwts.parser().verifyWith(Key).build().parseSignedClaims(token).getPayload());
    }

    // 토큰이 유효한지 또는 토큰이 만료되므로 빨리 수행합니다.
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        return extractClaims(token, Claims::getExpiration).before(new Date()); // 만료 시간
    }
}
