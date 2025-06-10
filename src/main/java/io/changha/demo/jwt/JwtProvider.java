package io.changha.demo.jwt;

import io.jsonwebtoken.Jwts;

public class JwtProvider {

    public String generateJwt(JwtReqeuest JwtReqeuest) {
        
        String jwt = Jwts.builder()
                         .subject(null)
    }

}
