package jin.usersmanagementsystem.controller;

import jin.usersmanagementsystem.dto.ReqRes;
import jin.usersmanagementsystem.entity.OurUsers;
import jin.usersmanagementsystem.service.UsersManagementService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserManagementController {

    @Autowired
    private UsersManagementService usersManagementService;

    /**
     * 회원가입
     */
    @PostMapping("/auth/register")  // HTTP POST 요청을 /auth/register 경로로 매핑합니다. 사용자가 회원가입을 시도할 때 이 경로를 통해 데이터를 전송
    public ResponseEntity<ReqRes> register(@RequestBody ReqRes reg) { // @RequestBody ReqRes reg: 클라이언트로부터 전송된 JSON 형식의 데이터를 ReqRes 객체로 바인딩
        return ResponseEntity.ok(usersManagementService.register(reg));  // register 메서드를 호출하여 사용자 등록을 처리하고, 결과를 HTTP 응답 본문에 담아 200 OK 상태 코드와 함께 반환
    }

    /**
     * 로그인
     */
    @PostMapping("/auth/login")  // HTTP POST 요청을 /auth/login 경로로 매핑합니다. 사용자가 로그인 요청을 보낼 때 이 경로를 사용
    public ResponseEntity<ReqRes> login(@RequestBody ReqRes reg) { // @RequestBody ReqRes reg: 클라이언트로부터 전송된 로그인 정보를 ReqRes 객체로 바인딩
        return ResponseEntity.ok(usersManagementService.login(reg));
    }

    /**
     * 모든 사용자 정보를 조회
     */
    @GetMapping("/admin/get-all-users")
    public ResponseEntity<ReqRes> getAllUsers() { // getAllUsers 메서드를 호출하여 모든 사용자 정보를 가져오고, 결과를 HTTP 응답 본문에 담아 200 OK 상태 코드와 함께 반환
        return ResponseEntity.ok(usersManagementService.getAllUsers());
    }

    /**
     * 특정 사용자 ID에 해당하는 사용자 정보를 조회
     */
    @GetMapping("/admin/get-users/{userId}") // userId 는 경로 변수로, 조회하고자 하는 사용자의 ID를 나타냅니다.
    public ResponseEntity<ReqRes> getUserById(@PathVariable Integer userId) { // @PathVariable Integer userId: 경로 변수 userId를 메서드의 매개변수로 받아 사용합니다.
        return ResponseEntity.ok(usersManagementService.getUsersById(userId)); // 특정 사용자 ID에 해당하는 사용자 정보를 가져오고, 결과를 HTTP 응답 본문에 담아 200 OK 상태 코드와 함께 반환
    }

    /**
     * 특정 사용자 ID에 해당하는 사용자 정보를 업데이트
     */
    @PutMapping("/admin/update/{userId}")                          // @RequestBody OurUsers reqres: 클라이언트로부터 전송된 업데이트 정보를 OurUsers 객체로 바인딩
    public ResponseEntity<ReqRes> updateUser(@PathVariable Integer userId, @RequestBody OurUsers reqres) { // @PathVariable Integer userId: 경로 변수 userId를 메서드의 매개변수로 받아 사용합니다.
        return ResponseEntity.ok(usersManagementService.updateUser(userId, reqres));
    }

    /**
     * 현재 인증된 사용자의 프로필 정보를 조회
     */
    @GetMapping("/admin/get-profile")
    public ResponseEntity<ReqRes> getMyProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // SecurityContextHolder.getContext().getAuthentication(): 현재 요청을 보낸 사용자의 인증 정보를 가져옵니다.
        String email = authentication.getName();           // 인증된 사용자의 이메일을 가져옵니다.
        ReqRes response = usersManagementService.getMyInfo(email); // 이메일을 기반으로 현재 사용자의 정보를 조회
        return ResponseEntity.status(response.getStatusCode()).body(response); // 조회된 사용자 정보를 응답 본문에 담아 적절한 HTTP 상태 코드와 함께 반환
    }

    /**
     * 특정 사용자 ID에 해당하는 사용자를 삭제
     */
    @DeleteMapping("/admin/delete/{userId}")
    public ResponseEntity<ReqRes> deleteUser(@PathVariable Integer userId) { // @PathVariable Integer userId: 경로 변수 userId를 메서드의 매개변수로 받아 사용합니다.
        return ResponseEntity.ok(usersManagementService.deleteUser(userId)); // 용자를 삭제하고, 결과를 HTTP 응답 본문에 담아 200 OK 상태 코드와 함께 반환
    }

}
