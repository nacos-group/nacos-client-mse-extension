package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.aliyun.credentials.models.Config;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class OidcRoleArnCredentialsProviderTest extends AbstractCredentialClientProviderTest {
    
    @Override
    protected ExtensionCredentialsProvider buildCredentialsProvider() {
        return new OidcRoleArnCredentialsProvider();
    }
    
    @Override
    protected void injectProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_ARN.getKey(), "role_arn");
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_SESSION_NAME.getKey(), "ram_role_arn_test");
        properties.setProperty(ExtensionAuthPropertyKey.OIDC_PROVIDER_ARN.getKey(), "oidc_provider_arn");
        properties.setProperty(ExtensionAuthPropertyKey.OIDC_TOKEN_FILE_PATH.getKey(), "oidc_token_file");
    }
    
    @Override
    protected void injectEnvProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_ARN.getEnvKey(), "role_arn");
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_SESSION_NAME.getEnvKey(), "ram_role_arn_test");
        properties.setProperty(ExtensionAuthPropertyKey.OIDC_PROVIDER_ARN.getEnvKey(), "oidc_provider_arn");
        properties.setProperty(ExtensionAuthPropertyKey.OIDC_TOKEN_FILE_PATH.getEnvKey(), "oidc_token_file");
    }
    
    @Test
    void generateCredentialsConfig() {
        initWithProperties();
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("oidc_role_arn", config.getType());
        assertEquals("role_arn", config.getRoleArn());
        assertEquals("ram_role_arn_test", config.getRoleSessionName());
        assertEquals("oidc_provider_arn", config.getOidcProviderArn());
        assertEquals("oidc_token_file", config.getOidcTokenFilePath());
        assertNull(config.getPolicy());
        assertEquals(3600, config.getRoleSessionExpiration());
    }
    
    @Test
    void generateCredentialsConfigByEnv() {
        initWithEnvProperties();
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("oidc_role_arn", config.getType());
        assertEquals("role_arn", config.getRoleArn());
        assertEquals("ram_role_arn_test", config.getRoleSessionName());
        assertEquals("oidc_provider_arn", config.getOidcProviderArn());
        assertEquals("oidc_token_file", config.getOidcTokenFilePath());
        assertNull(config.getPolicy());
        assertEquals(3600, config.getRoleSessionExpiration());
    }
}