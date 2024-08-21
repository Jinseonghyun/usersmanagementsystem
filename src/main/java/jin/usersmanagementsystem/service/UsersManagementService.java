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
    private UsersRepo usersRepo;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public ReqRes resgister(ReqRes registerationRequest) {
        ReqRes resp = new ReqRes();

        try {
            // 새로운 사용자와 동일한 사용자 만듬
            OurUsers ourUser = new OurUsers();
            ourUser.setEmail(registerationRequest.getEmail());
            ourUser.setCity(registerationRequest.getCity());
            ourUser.setRole(registerationRequest.getRole());
            ourUser.setName(registerationRequest.getName());
            ourUser.setPassword(passwordEncoder.encode(registerationRequest.getPassword()));
            OurUsers ourUsersResult = usersRepo.save(ourUser);

            if (ourUsersResult.getId() > 0) { // id 는 실제로 1 , 2, 3 이렇게 시작된다.
                // 성공적으로 저장되었음을 의미
                resp.setOurUsers(ourUsersResult);
                resp.setMessage("User Saved Successfully");
                resp.setStatusCode(200);
            }

        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setError(e.getMessage());
        }
        return resp;
    }
}
