package com.bloxmith.jwt.validator;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Main {
    private static final String GAME_JWK_URL = "https://android.api.staging.bloxmith.com/0.2.1/User/token/jwks";
    private static final String GAME_TOKEN_VALIDATE_URL = "https://android.api.staging.bloxmith.com/0.2.1/User/token/validate";
    private static final String GAME_TOKEN = "eyJhbGciOiJQUzI1NiIsImtpZCI6Ikl5OHcwdVhuVjhBZ0xfMkk4ZXR5ZFlCYW9zTHhPdVV1cjIyQ2JMV2JXR0EiLCJ0eXAiOiJKV1QifQ.eyJkYXRhIjoie1wiSWRcIjoxNTQ4ODUzMTYwNzQ2MDI5MDU2LFwiQWNjb3VudFwiOlwic2FtdWVsXCIsXCJOaWNrbmFtZVwiOlwiUDEzNTg1MzgxXCIsXCJJZGVudGlmZXJcIjpudWxsLFwiVXBkYXRlVGltZVwiOlwiMjAyMi0wNy0xOFQwMjoxMjoyNC40NjMyMzVaXCIsXCJDcmVhdGVUaW1lXCI6XCIyMDIyLTA3LTE4VDAyOjEyOjI0LjQ2MzIzNVpcIn0iLCJuYmYiOjE2NjQ4NzcwMTksImV4cCI6MTY2NTQ4MTgxOSwiaWF0IjoxNjY0ODc3MDE5LCJpc3MiOiJibG94bWl0aCIsImF1ZCI6IjE1NDg4NTMxNjA3NDYwMjkwNTYifQ.Ud4UDy76JuuV7XuQQV-8qglgrsCvUT8dWDvJdcZ50tkxmwqKruQEGLKF8rUz1jsL5iA5HentapqMFCjoQcZxbaFUDP5vO_oNwLMRMWel3AdiRKwiIQ91uFtVLMsQ1APnoTlNlZqI1n0WGt9-cJ_LpPNZx8wjzVR0cFnCMzCAWqNGfwH7aNTz4YgRj_tgn5PvHazcipLxWFbWe_sG5SK43Ek0oeXakcq74_PFv0_f8cD8RegLtGTltJrWxlOLf-wg9cbIoQfNdfcXM59WQujP2IbSR9TUU9ewEE89Nh5O1v6Z59kgC8jIXlodktVL_B6ZZXxdeEgpQTTYqdz3uZZeuA";
    private static final String SSO_TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAzNDYyQ0EwN0MxMDA5NjcxQTkzMjZGRTBEMzM1NTc5IiwidHlwIjoiYXQrand0In0.eyJuYmYiOjE2NjQ4NzQ2NzQsImV4cCI6MTY5NjQxMDY3NCwiaXNzIjoiaHR0cHM6Ly9hcGkuc3RhZ2luZy5ibG94bWl0aC5jb20vc3NvIiwiYXVkIjoiUHJvamVjdC1SIiwiY2xpZW50X2lkIjoic3NvX09wZXJhdGlvbiIsImlhdCI6MTY2NDg3NDY3NCwic2NvcGUiOlsiUHJvamVjdFIiXX0.KaJzOcUwEDq_xH6LYU5cEGndBBUISZc7ZEFINb_CNz4gUEsCmkzE3utkjhdBIC_BJuKA05tY0j0mqv8j1xU3dMU_nQ9xl-Ere0Mbcd6oAfO2bquA4u7AJ4sH2hvrdrHUe1mM4HXOppe45QFO7p_mFNMGB1FQKqbxc2_rDR-_lty-CKC4XtP7C_Tq_NP8Ly94nJSaSZswj3CT-NGohdtcnyXnGx1f0fIhKQgnPshWWCRILr8r1VIwHaWUVujuYzJs-OzjCt04ihjYlWPHZdLH206p4ZlwRKHAAAGDCWlW5TR-2zaUdYDhD9CcbgSbEmg3hAFge5O0lkBJqpDkauVd5Q";

    public static void main(String[] args) throws JoseException, IOException {
        /***Validate JWT Signature***/
        // Get JWKs
        HttpsJwks httpsJkws = new MyHttpsJwks(GAME_JWK_URL);
        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
        // be used to validate and process the JWT. But, in this case, provide it with
        // the HttpsJwksVerificationKeyResolver instance rather than setting the
        // verification key explicitly.
        JWT jwt = new JWT();
        DecodedJWT decodedJWT = jwt.decodeJwt(GAME_TOKEN);
        System.out.println(decodedJWT.getAudience().get(0));
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setExpectedIssuer("bloxmith") // whom the JWT needs to have been issued by
                .setExpectedAudience(decodedJWT.getAudience().get(0)) // to whom the JWT is intended for
                .setVerificationKeyResolver(httpsJwksKeyResolver) // verify the signature with the public key
                .build(); // create the JwtConsumer instance
        try {
            JwtContext context = jwtConsumer.process(GAME_TOKEN);
            System.out.println(context.getJwtClaims());

            /*** Check redis token status ***/
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(new URI(GAME_TOKEN_VALIDATE_URL))
                        .header("Content-Type", "application/json")
                        .header("Authorization", SSO_TOKEN)
                        .POST(HttpRequest.BodyPublishers.ofString("{\"accessToken\": \"" + GAME_TOKEN + "\"}"))
                        .build();
                HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 200) {
                    System.out.println(response.body());
                } else {
                    System.out.println(response.statusCode());
                }
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        } catch (InvalidJwtException e) {
            // Invalid Jwt Token
            throw new RuntimeException(e);
        }
    }
}
