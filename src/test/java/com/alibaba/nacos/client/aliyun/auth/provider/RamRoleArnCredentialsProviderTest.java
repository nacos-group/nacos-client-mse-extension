package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.aliyun.credentials.models.Config;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class RamRoleArnCredentialsProviderTest extends AbstractCredentialClientProviderTest {
    
    @Override
    protected ExtensionCredentialsProvider buildCredentialsProvider() {
        return new RamRoleArnCredentialsProvider();
    }
    
    @Override
    protected void injectProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_ID.getKey(), ACCESS_KEY_ID);
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_SECRET.getKey(), ACCESS_KEY_SECRET);
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_ARN.getKey(), "role_arn");
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_SESSION_NAME.getKey(), "ram_role_arn_test");
    }
    
    @Override
    protected void injectEnvProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_ID.getEnvKey(), ACCESS_KEY_ID);
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_SECRET.getEnvKey(), ACCESS_KEY_SECRET);
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_ARN.getEnvKey(), "role_arn");
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_SESSION_NAME.getEnvKey(), "ram_role_arn_test");
    }
    
    @Test
    void generateCredentialsConfig() {
        initWithProperties();
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("ram_role_arn", config.getType());
        assertEquals(ACCESS_KEY_ID, config.getAccessKeyId());
        assertEquals(ACCESS_KEY_SECRET, config.getAccessKeySecret());
        assertNull(config.getSecurityToken());
        assertEquals("role_arn", config.getRoleArn());
        assertEquals("ram_role_arn_test", config.getRoleSessionName());
        assertNull(config.getPolicy());
        assertEquals(3600, config.getRoleSessionExpiration());
    }
    
    @Test
    void generateCredentialsConfigFull() {
        initWithProperties();
        properties.setProperty(ExtensionAuthPropertyKey.SECURITY_TOKEN.getKey(), SECURITY_TOKEN);
        properties.setProperty(ExtensionAuthPropertyKey.POLICY.getKey(), "policy");
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_SESSION_EXPIRATION.getKey(), "360");
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("ram_role_arn", config.getType());
        assertEquals(ACCESS_KEY_ID, config.getAccessKeyId());
        assertEquals(ACCESS_KEY_SECRET, config.getAccessKeySecret());
        assertEquals(SECURITY_TOKEN, config.getSecurityToken());
        assertEquals("role_arn", config.getRoleArn());
        assertEquals("ram_role_arn_test", config.getRoleSessionName());
        assertEquals("policy", config.getPolicy());
        assertEquals(360, config.getRoleSessionExpiration());
    }
    
    @Test
    void generateCredentialsConfigByEnv() {
        initWithEnvProperties();
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("ram_role_arn", config.getType());
        assertEquals(ACCESS_KEY_ID, config.getAccessKeyId());
        assertEquals(ACCESS_KEY_SECRET, config.getAccessKeySecret());
        assertNull(config.getSecurityToken());
        assertEquals("role_arn", config.getRoleArn());
        assertEquals("ram_role_arn_test", config.getRoleSessionName());
        assertNull(config.getPolicy());
        assertEquals(3600, config.getRoleSessionExpiration());
    }
    
    @Test
    void generateCredentialsConfigByEnvFull() {
        initWithProperties();
        properties.setProperty(ExtensionAuthPropertyKey.SECURITY_TOKEN.getEnvKey(), SECURITY_TOKEN);
        properties.setProperty(ExtensionAuthPropertyKey.POLICY.getEnvKey(), "policy");
        properties.setProperty(ExtensionAuthPropertyKey.ROLE_SESSION_EXPIRATION.getEnvKey(), "360");
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("ram_role_arn", config.getType());
        assertEquals(ACCESS_KEY_ID, config.getAccessKeyId());
        assertEquals(ACCESS_KEY_SECRET, config.getAccessKeySecret());
        assertEquals(SECURITY_TOKEN, config.getSecurityToken());
        assertEquals("role_arn", config.getRoleArn());
        assertEquals("ram_role_arn_test", config.getRoleSessionName());
        assertEquals("policy", config.getPolicy());
        assertEquals(360, config.getRoleSessionExpiration());
    }
}