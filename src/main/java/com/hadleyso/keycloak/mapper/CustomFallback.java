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

public class CustomFallback extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper, TokenIntrospectionTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty targetAttribute = new ProviderConfigProperty();
        targetAttribute.setName("TARGET_ATTRIBUTE");
        targetAttribute.setLabel("Target Attribute");
        targetAttribute.setHelpText("Existing user attribute");
        targetAttribute.setType(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE);
        targetAttribute.setRequired(true);
        configProperties.add(targetAttribute);

        ProviderConfigProperty fallbackValue = new ProviderConfigProperty();
        fallbackValue.setName("FALLBACK_VALUE");
        fallbackValue.setLabel("Fallback Value");
        fallbackValue.setHelpText("If user attribute is empty or null, value to fallback on");
        fallbackValue.setType(ProviderConfigProperty.STRING_TYPE);
        fallbackValue.setRequired(true);
        configProperties.add(fallbackValue);

        ProviderConfigProperty claimName = new ProviderConfigProperty();
        claimName.setName("CLAIM_NAME");
        claimName.setLabel("Claim Name");
        claimName.setHelpText("Claim name to put in OIDC");
        claimName.setType(ProviderConfigProperty.STRING_TYPE);
        claimName.setRequired(true);
        configProperties.add(claimName);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, UPNMapper.class);

    }

    public static final String PROVIDER_ID = "hs-upn-custom-fallback";


    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "User attribute or hardcoded fallback";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Pull existing claim or use fallback value";
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        UserModel user = userSession.getUser();

        String userAttributeValue = user.getFirstAttribute(mappingModel.getConfig().getOrDefault("TARGET_ATTRIBUTE", "username"));
        if (userAttributeValue == null || userAttributeValue.isEmpty()) {
            userAttributeValue = mappingModel.getConfig().getOrDefault("FALLBACK_VALUE", "FALLBACK_VALUE");
        }

        if (userAttributeValue != null && !userAttributeValue.isEmpty()) {
            String claimName = mappingModel.getConfig().getOrDefault("CLAIM_NAME", "CLAIM");
            token.getOtherClaims().put(claimName, userAttributeValue);
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