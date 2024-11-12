package com.alibaba.nacos.client.aliyun.auth;

/**
 * Constants for aliyun extension auth.
 *
 * @author xiweng.yy
 */
public class ExtensionAuthConstants {
    
    /**
     * Original signature region id key, added by nacos-client 2.4.0.
     */
    public static final String SIGNATURE_REGION_ID_KEY = "signatureRegionId";
    
    public static final String SECURITY_TOKEN_HEADER = "Spas-SecurityToken";
    
    public static final String V4_SIGNATURE_UTIL_CLASS = "com.alibaba.nacos.client.auth.ram.utils.CalculateV4SigningKeyUtil";
    
    /**
     * Nacos properties keys
     */
    private static final String PREFIX = "alibabaCloud";
    
    public static final String SECRET_NAME_KEY = PREFIX + "SecretName";
    
    public static final String CREDENTIALS_URI_KEY = PREFIX + "CredentialsUri";
    
    public static final String OIDC_TOKEN_FILE_PATH_KEY = PREFIX + "OidcTokenFile";
    
    public static final String OIDC_PROVIDER_ARN_KEY = PREFIX + "OidcProviderArn";
    
    public static final String ROLE_SESSION_EXPIRATION_KEY = PREFIX + "RoleSessionExpiration";
    
    public static final String POLICY_KEY = PREFIX + "Policy";
    
    public static final String ROLE_SESSION_NAME_KEY = PREFIX + "RoleSessionName";
    
    public static final String ROLE_ARN_KEY = PREFIX + "RoleArn";
    
    public static final String SECURITY_TOKEN_KEY = PREFIX + "SecurityToken";
    
    public static final String ACCESS_KEY_SECRET_KEY = PREFIX + "AccessKeySecret";
    
    public static final String ACCESS_KEY_ID_KEY = PREFIX + "AccessKeyId";
    
    /**
     * Env properties keys.
     */
    private static final String ENV_PREFIX = "ALIBABA_CLOUD_";
    
    public static final String ENV_ACCESS_KEY_ID_KEY = ENV_PREFIX + "ACCESS_KEY_ID";
    
    public static final String ENV_ACCESS_KEY_SECRET_KEY = ENV_PREFIX + "ACCESS_KEY_SECRET";
    
    public static final String ENV_SECURITY_TOKEN_KEY = ENV_PREFIX + "SECURITY_TOKEN";
    
    public static final String ENV_SIGNATURE_REGION_ID_KEY = ENV_PREFIX + "SIGNATURE_REGION_ID";
    
    public static final String ENV_ROLE_ARN_KEY = ENV_PREFIX + "ROLE_ARN";
    
    public static final String ENV_ROLE_SESSION_NAME_KEY = ENV_PREFIX + "ROLE_SESSION_NAME";
    
    public static final String ENV_POLICY_KEY = ENV_PREFIX + "POLICY";
    
    public static final String ENV_ROLE_SESSION_EXPIRATION_KEY = ENV_PREFIX + "ROLE_SESSION_EXPIRATION";
    
    public static final String ENV_OIDC_PROVIDER_ARN_KEY = ENV_PREFIX + "OIDC_PROVIDER_ARN";
    
    public static final String ENV_OIDC_TOKEN_FILE_KEY = ENV_PREFIX + "OIDC_TOKEN_FILE";
    
    public static final String ENV_CREDENTIALS_URI_KEY = ENV_PREFIX + "CREDENTIALS_URI";
    
    public static final String ENV_SECRET_NAME_KEY = ENV_PREFIX + "SECRET_NAME";
}
