package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.Role;
import com.rishan.guardianstack.auth.model.SignUpMethod;

import java.util.List;

public record MasterAdminUserFilterOptions(
        List<Boolean> activeStatuses,
        List<Boolean> accountLockStatuses,
        List<Boolean> accountExpireStatuses,
        List<Boolean> credentialExpireStatuses,
        List<SignUpMethod> signUpMethods,
        List<Role> roles,
        List<String> sortOptions) {
    public static MasterAdminUserFilterOptions create(
            List<SignUpMethod> signUpMethods,
            List<Role> roles) {

        return new MasterAdminUserFilterOptions(
                List.of(true, false),
                List.of(true, false),
                List.of(true, false),
                List.of(true, false),
                signUpMethods,
                roles,
                List.of("userId", "username", "createdAt", "createdBy"));
    }
}