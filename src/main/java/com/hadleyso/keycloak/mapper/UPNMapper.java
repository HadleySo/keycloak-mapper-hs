package com.hadleyso.keycloak.mapper;

import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.IDToken;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;

public class UPNMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty domain = new ProviderConfigProperty();
        domain.setName("DOMAIN_CONFIG");
        domain.setLabel("Domain");
        domain.setHelpText("Domain to append when user has no email (e.g. acme.com)");
        domain.setType(ProviderConfigProperty.STRING_TYPE);
        domain.setRequired(true);

        configProperties.add(domain);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, UPNMapper.class);

    }

    public static final String PROVIDER_ID = "hs-upn-mapper";


    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "UPN as email fallback";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Maps the user's username with '@' and a specified domain name to email claim if email not available";
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        UserModel user = userSession.getUser();

        String email = user.getEmail();
        if (email == null || email.isEmpty()) {
            // Fallback: build email from username
            String username = user.getUsername();
            if (username != null && !username.isEmpty()) {
                String domain = mappingModel.getConfig().getOrDefault("DOMAIN_CONFIG", "example.com");
                email = username + "@" + domain;
            }
        }

        if (email != null && !email.isEmpty()) {
            token.getOtherClaims().put("email", email);
        }
    }


    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo, boolean introspectionEndpoint) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        if (idToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        if (userInfo) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
        if (introspectionEndpoint) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_INTROSPECTION, "true");
        mapper.setConfig(config);
        return mapper;
    }

}