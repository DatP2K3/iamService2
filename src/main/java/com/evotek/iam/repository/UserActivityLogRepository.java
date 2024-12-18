package com.evotek.iam.repository;

import com.evotek.iam.model.UserActivityLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserActivityLogRepository extends JpaRepository<UserActivityLog, Integer> {
}
