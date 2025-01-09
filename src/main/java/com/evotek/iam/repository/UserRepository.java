package com.evotek.iam.repository;

import com.evotek.iam.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Integer>,  UserRepositoryCustom {
    @Query("from User e where e.deleted = false and lower(e.username) = lower(:username)")
    Optional<User> findByUsername(@Param("username") String username);
    Optional<User> findBySelfUserID(int selfUserID);
    Optional<User> findByEmail(String email);
}
