package com.hadleyso.keycloak.mapper;

import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EmailOverride extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {

    public static final String PROVIDER_ID = "hs-email-override";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty overrideMap = new ProviderConfigProperty();
        overrideMap.setName("OVERRIDE_MAP");
        overrideMap.setLabel("Overrides");
        overrideMap.setHelpText("Emails to replace");
        overrideMap.setType(ProviderConfigProperty.MAP_TYPE);
        overrideMap.setRequired(true);

        configProperties.add(overrideMap);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, EmailOverride.class);

    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Email override for specific users";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Email override for specific users";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        UserModel user = userSession.getUser();

        String email = user.getEmail();
        if (email != null && !email.isEmpty()) {
            Map<String, String> config = mappingModel.getConfig();
            String json = config.get("OVERRIDE_MAP");

            if (json == null) {
                token.getOtherClaims().put("email", email);
                return;
            }

            Map<String, String> map = new HashMap<>();
            try {
                List<Map<String, String>> list =
                    JsonSerialization.readValue(json, List.class);

                for (Map<String, String> entry : list) {
                    map.put(entry.get("key"), entry.get("value"));
                }
            } catch (IOException e) {
                // https://github.com/keycloak/keycloak/blob/dd9ad305cad6084ba5af357eaaa8857a22695103/server-spi/src/main/java/org/keycloak/models/IdentityProviderMapperModel.java#L94
                throw new RuntimeException("Could not deserialize json: " + json, e);
            }

            if (map.containsKey(email)) {
                String emailReplace = map.get(email);
                token.getOtherClaims().put("email", emailReplace);
            } else {
                token.getOtherClaims().put("email", email);
                return;
            }

        }
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo,
            boolean introspectionEndpoint) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken)
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        if (idToken)
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        if (userInfo)
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
        if (introspectionEndpoint)
            config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "true");
        mapper.setConfig(config);
        return mapper;
    }
}