package authentication.jwt.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Slf4j
public class JwtTokenizer {
    /*
    * Plain Text 형태인 Secret Key의 byte[]를 Base64 형식의 문자열로 변경
    * */
    public String encodeBase64SecretKey(String secretKey){
        String encode = Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
        log.info("encodeBase64SecretKey Method 실행 { " +"secretKEY = "+ secretKey + " secretKEY.Byte = "+ secretKey.getBytes().length + " Base64 Encode = " + encode+" }");
        return encode;
    }

    /*
    * Access Token을 생성하는메서드
    * 인증된 사용자에게 JWT를 발급해주기 위한 역할
    * */
    public String generateAccessToken(Map<String, Object> claims, String subject, Date expiration, String base64EncodedSecretKey){

        Key key = getKeyFormBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setClaims(claims) // Custom Claims를 추가 (인증된 사용자와 관련된 정보)
                .setSubject(subject) // JWT에 대한 제목을 추가
                .setIssuedAt(Calendar.getInstance().getTime()) // JWT 발행 일자 설정
                .setExpiration(expiration) // JWT 만료일자 설정
                .signWith(key) // 서명을 위한 Key 객체를 넣어준다.
                .compact(); // JWT를 생성하고 직렬화해줌
    }

    /*
     * Refresh Token을 생성하는 메서드
     * Access Token이 만료되었을 경우 Access Token을 새로 생성할 수 있게해주는 역할
     * */
    public String generateRefreshToken(String subject, Date expiration, String base64EncodedSecretKey){
        Key key = getKeyFormBase64EncodedKey(base64EncodedSecretKey);

        return Jwts.builder()
                .setSubject(subject) // JWT에 대한 제목을 추가
                .setIssuedAt(Calendar.getInstance().getTime()) // JWT 발행 일자 설정
                .setExpiration(expiration) // JWT 만료일자 설정
                .signWith(key) // 서명을 위한 Key 객체를 넣어준다.
                .compact(); // JWT를 생성하고 직렬화해줌
    }

    /*
    * JWT 검증을 위한 메서드 추가
    * */
    public void verifySignature(String jws, String base64EncodedSecretKey){
        Key key = getKeyFormBase64EncodedKey(base64EncodedSecretKey);

        Jwts.parserBuilder()
                .setSigningKey(key) // 서명에 사용된 Secret Key를 설정
                .build()
                .parseClaimsJws(jws); // JWT를 파싱해서 Claims를 얻는다.
    }

    /*
    * JWT의 서명에 사용할 Secret Key를 생성해주는 메서드
    * */
    private Key getKeyFormBase64EncodedKey(String base64EncodedSecretKey){
        byte[] keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey); // 디코딩 진행

        // 테스트 임시코드
//        String test = "";
//        for (byte s : keyBytes){
//            test += (char)s;
//        }
//        System.out.println(test);
//        System.out.println(keyBytes.length);
        // HMAC-SHA 스펙확인용 테스트코드

        Key key = (Key) Keys.hmacShaKeyFor(keyBytes); // HMAC 알고리즘을 적용한 Key 객체 생성
        return key;
    }
}
