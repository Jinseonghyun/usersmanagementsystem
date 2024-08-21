package jin.usersmanagementsystem.service;

import jin.usersmanagementsystem.dto.ReqRes;
import jin.usersmanagementsystem.entity.OurUsers;
import jin.usersmanagementsystem.repository.UsersRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

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

    /**
     * 회원가입
     */
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

    /**
     * 로그인
     */
    public ReqRes login(ReqRes loginRequest) {
        ReqRes response =  new ReqRes();
        try {    // authenticationManager.authenticate를 사용하여 사용자 인증을 시도, 제공된 이메일과 비밀번호를 확인하여 사용자를 인증합니다. 자격 증명이 정확하면 사용자는 인증된 것으로 간주
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            var user = usersRepo.findByEmail(loginRequest.getEmail()).orElseThrow(); // 제공된 이메일을 사용하여 데이터베이스에서 사용자 세부 정보를 검색
            var jwt = jwtUtils.generateToken(user);                                  // 인증된 사용자를 위한 JWT 토큰을 생성
            var refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user); // 인증된 사용자를 위한 새로 고침 토큰을 생성
            response.setStatusCode(200);     // HTTP 상태 코드를 200으로 설정하여 작업 성공을 나타냄
            response.setToken(jwt);          // 생성된 JWT 토큰을 응답에 첨부
            response.setRefreshToken(refreshToken);       // 성된 새로 고침 토큰을 응답에 첨부
            response.setExpirationTime("24Hrs");          // 토큰 만료 시간을 24시간으로 설정
            response.setMessage("Successfully Logged In");  // 성공 메시지를 설정

            // 인증이 실패하거나 오류가 발생하면 catch 블록은 500 상태 코드를 설정하고 오류 메시지를 응답에 첨부
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setError(e.getMessage());
        }
        return response;
    }

    /**
     * refreshToken 갱신
     */
    public ReqRes refreshToken(ReqRes refreshTokenReqiest){
        ReqRes response = new ReqRes();
        try{
            String ourEmail = jwtUtils.extractUsername(refreshTokenReqiest.getToken());  // jwtUtils.extractUsername: 제공된 토큰에서 이메일/사용자 이름을 추출
            OurUsers users = usersRepo.findByEmail(ourEmail).orElseThrow();              //  이메일과 연결된 사용자를 검색
            if (jwtUtils.isTokenValid(refreshTokenReqiest.getToken(), users)) {      // jwtUtils.isTokenValid: 제공된 새로 고침 토큰이 여전히 유효한지 확인
                var jwt = jwtUtils.generateToken(users);            // jwtUtils.generateToken: 새로 고침 토큰이 유효한 경우 사용자를 위한 새 JWT 토큰을 생성
                response.setStatusCode(200);
                response.setToken(jwt);      // 응답에 새 JWT 토큰을 설정
                response.setRefreshToken(refreshTokenReqiest.getToken());
                response.setExpirationTime("24Hr");
                response.setMessage("Successfully Refreshed Token");
            }
            response.setStatusCode(200);
            return response;

            // 새로 고침 토큰이 유효하지 않거나 오류가 발생하면 catch 블록이 예외를 처리하고 적절한 오류 메시지와 상태 코드를 설정
        }catch (Exception e){
            response.setStatusCode(500);
            response.setMessage(e.getMessage());
            return response;
        }
    }

    /**
     * 모든 사용자 조회
     */
    public ReqRes getAllUsers() {
        ReqRes reqRes = new ReqRes();

        try {
            List<OurUsers> result = usersRepo.findAll(); // 데이터베이스에서 모든 사용자 레코드를 가져옵니다.
            if (!result.isEmpty()) {
                reqRes.setOurUsersList(result); // 사용자가 발견되면 응답에 사용자 목록을 설정
                reqRes.setStatusCode(200);
                reqRes.setMessage("Successful");
            } else {
                reqRes.setStatusCode(404);
                reqRes.setMessage("No users found");
            }
            return reqRes;
        } catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred: " + e.getMessage());
            return reqRes;
        }
    }

    /**
     * ID로 사용자 조회
     */
    public ReqRes getUsersById(Integer id) {
        ReqRes reqRes = new ReqRes();
        try {
            OurUsers usersById = usersRepo.findById(id).orElseThrow(() -> new RuntimeException("User Not found"));  // 제공된 ID와 연결된 사용자를 가져옵니다.
            reqRes.setOurUsers(usersById);  // 사용자를 찾으면 응답에 사용자의 세부 정보가 설정
            reqRes.setStatusCode(200);
            reqRes.setMessage("Users with id '" + id + "' found successfully");
        } catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred: " + e.getMessage());
        }
        return reqRes;
    }

    /**
     * 사용자 삭제
     */
    public ReqRes deleteUser(Integer userId) {
        ReqRes reqRes = new ReqRes();
        try {
            Optional<OurUsers> userOptional = usersRepo.findById(userId);  // 삭제할 사용자를 찾습니다.
            if (userOptional.isPresent()) {
                usersRepo.deleteById(userId);   // 사용자가 발견되면 usersRepo.deleteById(userId)를 사용하여 삭제
                reqRes.setStatusCode(200);
                reqRes.setMessage("User deleted successfully"); // 삭제에 성공하면 성공 메시지와 함께 상태 코드 200이 반환
            } else {
                reqRes.setStatusCode(404);
                reqRes.setMessage("User not found for deletion");  // 사용자를 찾을 수 없는 경우 해당 메시지와 함께 404 상태 코드가 반환
            }
        } catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred while deleting user: " + e.getMessage()); // 삭제 과정에서 오류가 발생하면 상태 코드 500과 오류 메시지가 반환
        }
        return reqRes;
    }

    /**
     * 사용자 업데이트
     */
    public ReqRes updateUser(Integer userId, OurUsers updatedUser) {
        ReqRes reqRes = new ReqRes();
        try {
            Optional<OurUsers> userOptional = usersRepo.findById(userId);  // 업데이트할 사용자를 찾습니다.
            if (userOptional.isPresent()) {
                OurUsers existingUser = userOptional.get();
                existingUser.setEmail(updatedUser.getEmail());  // 사용자를 찾으면 해당 사용자의 세부정보(이메일, 이름, 도시, 역할)가 업데이트
                existingUser.setName(updatedUser.getName());
                existingUser.setCity(updatedUser.getCity());
                existingUser.setRole(updatedUser.getRole());


                if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {

                    existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));  // 새 비밀번호가 제공되면 업데이트되기 전에 passwordEncoder.encode를 사용하여 인코딩
                }

                OurUsers savedUser = usersRepo.save(existingUser);  // 업데이트 후 사용자는 데이터베이스에 다시 저장
                reqRes.setOurUsers(savedUser);
                reqRes.setStatusCode(200);
                reqRes.setMessage("User updated successfully");  // 업데이트가 성공하면 200 상태 코드와 성공 메시지를 반환
            } else {
                reqRes.setStatusCode(404);
                reqRes.setMessage("User not found for update");  // 사용자가 발견되지 않으면 404 상태 코드와 적절한 메시지를 반환
            }
        } catch (Exception e) {
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred while updating user: " + e.getMessage()); // 업데이트 중 오류가 발생하면 500 상태 코드와 오류 메시지를 반환
        }
        return reqRes;
    }

    /**
     * 내 정보 조회
     */
    public ReqRes getMyInfo(String email){
        ReqRes reqRes = new ReqRes();
        try {
            Optional<OurUsers> userOptional = usersRepo.findByEmail(email); // 제공된 이메일과 연관된 사용자를 검색
            if (userOptional.isPresent()) {
                reqRes.setOurUsers(userOptional.get());  // 사용자가 발견되면 사용자의 세부 정보를 응답에 설정
                reqRes.setStatusCode(200);              // 사용자가 검색된 경우 성공 상태 코드 200을 설정
                reqRes.setMessage("successful");
            } else {
                reqRes.setStatusCode(404);
                reqRes.setMessage("User not found for update");    // 용자가 발견되지 않으면 404 상태 코드와 적절한 메시지를 반환
            }

        }catch (Exception e){
            reqRes.setStatusCode(500);
            reqRes.setMessage("Error occurred while getting user info: " + e.getMessage()); // 오류가 발생하면 500 상태 코드와 오류 메시지를 반환
        }
        return reqRes;

    }
}
