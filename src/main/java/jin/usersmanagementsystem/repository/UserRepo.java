package jin.usersmanagementsystem.repository;

import jin.usersmanagementsystem.entity.OurUsers;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<OurUsers, Integer> {

    // 이메일을 찾기 위한 메서드
    Optional<OurUsers> findByEmail(String email);

}
