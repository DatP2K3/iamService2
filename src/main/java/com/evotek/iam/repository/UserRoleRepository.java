package com.evotek.iam.repository;

import com.evotek.iam.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRoleRepository extends JpaRepository<UserRole, Integer> {
    Optional<UserRole> findByUserId(int selfUserID);
}
