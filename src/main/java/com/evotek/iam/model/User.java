package com.evotek.iam.model;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    int id;

    @Column(name = "full_name")
    String fullName;

    @Column(name = "birth_date")
    LocalDate birthDate;

    @Column(name = "phone")
    String phone;

    @Column(name = "address")
    String address;

    @Column(name = "email")
    String email;

    @Column(name = "password")
    String password;

    @Column(name = "avatar")
    String avatar;

    @ManyToOne(cascade = {CascadeType.PERSIST,
            CascadeType.MERGE, CascadeType.DETACH})
    Role role;
}