package com.evotek.iam.model;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "user_activity_logs")
public class UserActivityLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    int id;

    @Column(name = "user_id")
    int userId;

    @Column(name = "activity")
    String activity;

    @Column(name = "created_at")
    LocalDateTime createdAt;
}
