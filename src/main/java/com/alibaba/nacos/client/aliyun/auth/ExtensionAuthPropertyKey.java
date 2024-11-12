package com.alibaba.nacos.client.aliyun.auth;

/**
 * Aliyun Extension Auth Property Key.
 *
 * @author xiweng.yy
 */
public enum ExtensionAuthPropertyKey {
    
    ACCESS_KEY_ID(ExtensionAuthConstants.ACCESS_KEY_ID_KEY, ExtensionAuthConstants.ENV_ACCESS_KEY_ID_KEY),
    
    ACCESS_KEY_SECRET(ExtensionAuthConstants.ACCESS_KEY_SECRET_KEY, ExtensionAuthConstants.ENV_ACCESS_KEY_SECRET_KEY),
    
    SECURITY_TOKEN(ExtensionAuthConstants.SECURITY_TOKEN_KEY, ExtensionAuthConstants.ENV_SECURITY_TOKEN_KEY),
    
    SIGNATURE_REGION_ID(ExtensionAuthConstants.SIGNATURE_REGION_ID_KEY,
            ExtensionAuthConstants.ENV_SIGNATURE_REGION_ID_KEY),
    
    ROLE_ARN(ExtensionAuthConstants.ROLE_ARN_KEY, ExtensionAuthConstants.ENV_ROLE_ARN_KEY),
    
    ROLE_SESSION_NAME(ExtensionAuthConstants.ROLE_SESSION_NAME_KEY, ExtensionAuthConstants.ENV_ROLE_SESSION_NAME_KEY),
    
    POLICY(ExtensionAuthConstants.POLICY_KEY, ExtensionAuthConstants.ENV_POLICY_KEY),
    
    ROLE_SESSION_EXPIRATION(ExtensionAuthConstants.ROLE_SESSION_EXPIRATION_KEY,
            ExtensionAuthConstants.ENV_ROLE_SESSION_EXPIRATION_KEY),
    
    OIDC_PROVIDER_ARN(ExtensionAuthConstants.OIDC_PROVIDER_ARN_KEY, ExtensionAuthConstants.ENV_OIDC_PROVIDER_ARN_KEY),
    
    OIDC_TOKEN_FILE_PATH(ExtensionAuthConstants.OIDC_TOKEN_FILE_PATH_KEY,
            ExtensionAuthConstants.ENV_OIDC_TOKEN_FILE_KEY),
    
    CREDENTIALS_URI(ExtensionAuthConstants.CREDENTIALS_URI_KEY, ExtensionAuthConstants.ENV_CREDENTIALS_URI_KEY),
    
    SECRET_NAME(ExtensionAuthConstants.SECRET_NAME_KEY, ExtensionAuthConstants.ENV_SECRET_NAME_KEY);
    
    private final String key;
    
    private final String envKey;
    
    ExtensionAuthPropertyKey(String key, String envKey) {
        this.key = key;
        this.envKey = envKey;
    }
    
    public String getKey() {
        return key;
    }
    
    public String getEnvKey() {
        return envKey;
    }
}
