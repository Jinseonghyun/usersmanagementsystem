package jin.usersmanagementsystem.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "ourusers")
@Data
public class OurUsers implements UserDetails { // UserDetails : Spring Security 에서 사용자 정보를 본다.

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)

    private Integer id; // null이 들어올 수 있는 상황에, Wrapper 형식인 Integer
    private String email;
    private String name;
    private String password;
    private String city;
    private String role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role)); // 새 목록을 반환 , 이는 단순 부여된 권한이자 규칙이 된다. // 규칙에 따라 사용자가 우리 애플리케이션에서 가지 ㄹ권한은 이것
    }

    @Override
    public String getUsername() {
        return email;  //  이메일이 사용자가 된다.
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
