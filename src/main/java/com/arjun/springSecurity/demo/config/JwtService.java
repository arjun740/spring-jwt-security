package com.arjun.springSecurity.demo.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY="fPXviMgajSJh1poWLU0kOaoO1CRGNjFJUJQAhV+A5Hd9ijh6jcvdG4/urJVPdpGisFNgRWZ8ZXD5nkFbkZF0UUiLcOMj2RFqQuwOtmJdv59qwrPeI0YyDFb2WJv/Ch9VPXouxaHhWgcuVCn1SuK/u1JeZtk2rEKILHl95TGfS/kNkqvj1dCVA/vz1DG82A6J7nINkjnrjeL0qIbLmD4n3gZCJxH2EOTP+wqQfKl/ZSSvXmvH1lb28zzyfJn7YbJ3SxbWEtKQUQrXaYvCm6uKQpimQkiLjuKlxCBVvmnDEII3euiP90o+oVw/6Bac471X1P/s1aKpSmoe4MKZz6mORq/aostSFqstyE0kxB9VWNTyPOCAAYGCZXRu7ZipMwIPGdrocXwUYeZu5ZOkDoJq5oqR/nFpaW3jPGGR/A1XUHe5cBq2QzyrQEzsriA3fmnn/GFEUfMbZcsD7R8vJCwadmd03G3akZ8pJbWu+eWeOd0vxvcNUG5+l51HbfPmAgcAfW0IaQIHcfOYP8Ug3TQ/5RqGazkptT6pJEr02tnW7VAs9vXH8ZCaeh58OSaSgc6zZlm8DY/zpHH4BJYiXailYgsOw655vblOw/iuB1NCXNhxzIISZIPeElwGWAG0eoyHcPaf7HQMJi+c0IQ9sw9nwcfC6A5PIaKWX0bvzseF1r0dAu4LZCzwUMUZu+BKimDx\n";
    public String extractUsername(String token) {

        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String,Object> extractClaims, UserDetails userDetails){
    return  Jwts
            .builder()
            .setClaims(extractClaims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
            .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return  (username.equals(userDetails.getUsername()) && !istokenExpired(token));
    }

    private boolean istokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
