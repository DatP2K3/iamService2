package com.evotek.iam.model;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Collection;
import java.util.HashSet;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    int id;

    @Column(name = "name")
    String name;

    @OneToMany(cascade = {CascadeType.PERSIST, CascadeType.MERGE,
            CascadeType.DETACH, CascadeType.REFRESH})
    @JoinColumn(name = "role_id")
    Collection<User> users = new HashSet<>();

    public void assignRoleToUser(User user){
        user.setRole(this);
        if(users == null){
            users = new HashSet<>();
        }
        this.getUsers().add(user);
    }

    public void removeUserFromRole(User user){
        this.getUsers().remove(user);
    }
}
