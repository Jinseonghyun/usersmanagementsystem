package jin.usersmanagementsystem.service;

import jin.usersmanagementsystem.repository.UsersRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class OurUserDetailsService implements UserDetailsService {

    // 사용자 정보를 데이터베이스에서 가져오기 위한 레포지토리를 참조
    @Autowired
    private UsersRepo usersRepo;

    // 사용자 이름(여기서는 이메일)을 기반으로 사용자 정보를 로드
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // UsernameNotFoundException 해당 사용자 이름을 가진 사용자가 없을 경우 예외를 던집니다.
        return usersRepo.findByEmail(username).orElseThrow(); // 주어진 이메일로 사용자를 찾는다. // 사용자가 존재하지 않으면 UsernameNotFoundException 예외를 던집니다.
    }
}
