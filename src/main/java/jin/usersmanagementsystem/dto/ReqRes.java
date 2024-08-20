package jin.usersmanagementsystem.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import jin.usersmanagementsystem.entity.OurUsers;
import lombok.Data;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL) // 데이터가 생성 될 때 주석을 달겠다.
@JsonIgnoreProperties(ignoreUnknown = true) // 없음을 무시한다
public class ReqRes {

    private int statusCode;
    private String error;
    private String message;
    private String token;
    private String refreshToken;
    private String expirationTime;
    private String name;
    private String city;
    private String role;
    private String email;
    private String password;
    private OurUsers ourUsers; // 사용자
    private List<OurUsers> ourUsersList; // 사용자 목록
}
