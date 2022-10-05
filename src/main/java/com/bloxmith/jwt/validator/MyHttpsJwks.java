package com.bloxmith.jwt.validator;

import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.util.List;

public class MyHttpsJwks extends HttpsJwks
{
    public MyHttpsJwks(String location)
    {
        super(location);
    }

    @Override
    public List<JsonWebKey> getJsonWebKeys() throws JoseException, IOException
    {
        System.out.println(super.getJsonWebKeys());
        List<JsonWebKey> jsonWebKeys = super.getJsonWebKeys();
        for (JsonWebKey jwk : jsonWebKeys)
        {
            jwk.setUse(null);
            jwk.setKeyOps(null);
        }
        return jsonWebKeys;
    }
}