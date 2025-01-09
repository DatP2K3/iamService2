package com.evotek.iam.service.common;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User user =  super.loadUser(userRequest);
        System.out.println("CustomOAuth2UserService invoked");
        return user;
    }
//    private final UserRepository userRepository;
//
//    public User processOAuth2User(OAuth2User oauth2User) {
//        String providerId = oauth2User.getAttribute("sub"); // ID từ Google OAuth2
//        String email = oauth2User.getAttribute("email"); // Email người dùng
//        String name = oauth2User.getAttribute("name"); // Tên người dùng
//
//        // Kiểm tra xem người dùng đã tồn tại trong hệ thống chưa
//        Optional<User> existingUser = userRepository.findByEmail(email);
//        if (existingUser.isPresent()) {
//            User user = existingUser.get();
//            user.setProviderId(providerId);
//            return userRepository.save(user);  // Cập nhật thông tin người dùng
//        } else {
//            // Nếu người dùng chưa tồn tại, tạo mới người dùng
//            User newUser = User.builder()
//                    .providerId(providerId)
//                    .username(email)
//                    .email(email)
//                    .firstName("")
//                    .lastName("")
//                    .locked(false)
//                    .deleted(false)
//                    .provider("google")
//                    .build();
//
//            return userRepository.save(newUser);  // Lưu người dùng mới vào cơ sở dữ liệu
//        }
//    }
}
