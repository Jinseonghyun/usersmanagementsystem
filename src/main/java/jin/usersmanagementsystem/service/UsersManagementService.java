package jin.usersmanagementsystem.service;

import jin.usersmanagementsystem.dto.ReqRes;
import jin.usersmanagementsystem.entity.OurUsers;
import jin.usersmanagementsystem.repository.UsersRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UsersManagementService {

    @Autowired
    private UsersRepo usersRepo;   // 사용자 정보를 관리하는 데이터베이스

    @Autowired
    private JWTUtils jwtUtils;     //  JWT(JSON Web Token)를 생성하고 검증하는 유틸리티 클래스

    @Autowired
    private AuthenticationManager authenticationManager;   // Spring Security에서 인증을 처리하는 매니저

    @Autowired
    private PasswordEncoder passwordEncoder;   // 비밀번호를 암호화하는 인코더

    public ReqRes register(ReqRes registrationRequest) {
        ReqRes resp = new ReqRes();  // ReqRes: 사용자 등록 요청 정보를 담고 있는 객체입니다. 사용자의 이메일, 도시, 역할, 이름, 비밀번호 등의 정보가 포함
                                     // resp: 응답 정보를 담기 위한 객체입니다. 등록 성공 또는 실패 시 응답 메시지와 상태 코드를 포함
        try {
            // 사용자 객체 생성 및 저장
            OurUsers ourUser = new OurUsers();     // OurUsers: 새로 등록할 사용자 객체입니다. 이 객체는 데이터베이스에 저장될 사용자 정보를 담습니다.
            ourUser.setEmail(registrationRequest.getEmail());
            ourUser.setCity(registrationRequest.getCity());
            ourUser.setRole(registrationRequest.getRole());
            ourUser.setName(registrationRequest.getName());
            ourUser.setPassword(passwordEncoder.encode(registrationRequest.getPassword())); // 입력된 비밀번호를 암호화하여 저장
            OurUsers ourUsersResult = usersRepo.save(ourUser);

            if (ourUsersResult.getId() > 0) { // 데이터베이스에 사용자가 성공적으로 저장되었는지 확인합니다. 데이터베이스에 저장되면 사용자 ID는 1 이상의 값
                // 성공적으로 저장되었음을 의미
                resp.setOurUsers(ourUsersResult);    // 응답 객체에 저장된 사용자 정보를 설정
                resp.setMessage("User Saved Successfully");  // 성공 메시지를 설정
                resp.setStatusCode(200);          // HTTP 상태 코드 200(성공)을 설정
            }

            // 예외 처리
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setError(e.getMessage());
        }
        // 응답 반환
        return resp; // return resp: 응답 객체를 반환합니다. 이 객체에는 등록 결과(성공 또는 실패)에 대한 정보가 포함
    }
}
