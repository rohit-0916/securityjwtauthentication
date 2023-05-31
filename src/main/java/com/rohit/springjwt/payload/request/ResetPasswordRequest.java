package com.rohit.springjwt.payload.request;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ResetPasswordRequest {
    private String resetToken;
    private String newPassword;

}
