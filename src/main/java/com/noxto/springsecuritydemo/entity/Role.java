package com.noxto.springsecuritydemo.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Entity
@Table(name = "roles")
@NoArgsConstructor
public class Role implements GrantedAuthority {
    @Id
    @Column(name = "role_id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer roleId;

    @Column(name = "role")
    @Getter
    private String role;

    public Role(String role){
        this.role = role;
    }

    public Role(Integer roleId, String role){
        this.roleId = roleId;
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return this.role;
    }

    public void setRole(String role){
        this.role = role;
    }

    public void setRoleId(Integer roleId){
        this.roleId = roleId;
    }

    @Override
    public String toString() {
        return "Role{" +
                "roleId=" + roleId +
                ", role='" + role + '\'' +
                '}';
    }
}
