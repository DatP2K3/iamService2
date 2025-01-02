package com.evotek.iam.repository;

import com.evotek.iam.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer> {
    boolean existsByEmail(String email);
    Optional<User> findByUsername(String username);
    Optional<User> findBySelfUserID(int selfUserID);
    Page<User> findByUsernameContainingIgnoreCase(String username, Pageable pageable);
}
