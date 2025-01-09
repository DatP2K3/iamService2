package com.evotek.iam.service.common;

import com.evotek.iam.model.User;
import com.evotek.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    public User processOAuth2User(OAuth2User oauth2User) {
        String providerId = oauth2User.getAttribute("sub"); // ID từ Google OAuth2
        String email = oauth2User.getAttribute("email"); // Email người dùng
        String name = oauth2User.getAttribute("name"); // Tên người dùng

        // Kiểm tra xem người dùng đã tồn tại trong hệ thống chưa
        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isPresent()) {
            User user = existingUser.get();
            user.setProviderId(providerId);
            return userRepository.save(user);  // Cập nhật thông tin người dùng
        } else {
            // Nếu người dùng chưa tồn tại, tạo mới người dùng
            User newUser = User.builder()
                    .providerId(providerId)
                    .username(email)
                    .email(email)
                    .firstName("")
                    .lastName("")
                    .locked(false)
                    .deleted(false)
                    .provider("google")
                    .build();

            return userRepository.save(newUser);  // Lưu người dùng mới vào cơ sở dữ liệu
        }
    }
}
