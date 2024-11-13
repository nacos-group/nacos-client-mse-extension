package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class StsTokenCredentialsProviderTest extends AbstractCredentialsProviderTest {
    
    @Override
    protected ExtensionCredentialsProvider buildCredentialsProvider() {
        return new StsTokenCredentialsProvider();
    }
    
    @Override
    protected void injectProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_ID.getKey(), ACCESS_KEY_ID);
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_SECRET.getKey(), ACCESS_KEY_SECRET);
        properties.setProperty(ExtensionAuthPropertyKey.SECURITY_TOKEN.getKey(), SECURITY_TOKEN);
        properties.setProperty(ExtensionAuthPropertyKey.SIGNATURE_REGION_ID.getKey(), SIGNATURE_REGION_ID);
    }
    
    @Override
    protected void injectEnvProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_ID.getEnvKey(), ACCESS_KEY_ID);
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_SECRET.getEnvKey(), ACCESS_KEY_SECRET);
        properties.setProperty(ExtensionAuthPropertyKey.SECURITY_TOKEN.getEnvKey(), SECURITY_TOKEN);
        properties.setProperty(ExtensionAuthPropertyKey.SIGNATURE_REGION_ID.getEnvKey(), SIGNATURE_REGION_ID);
    }
    
    @Test
    void getCredentialsForNacosClient() {
        initWithProperties();
        ExtensionRamContext context = credentialsProvider.getCredentialsForNacosClient();
        assertEquals(ACCESS_KEY_ID, context.getAccessKey());
        assertEquals(ACCESS_KEY_SECRET, context.getSecretKey());
        assertEquals(SECURITY_TOKEN, context.getSecurityToken());
        assertEquals(SIGNATURE_REGION_ID, context.getExtensionSignatureRegionId());
    }
    
    @Test
    void getCredentialsForNacosClientWithEnv() {
        initWithEnvProperties();
        ExtensionRamContext context = credentialsProvider.getCredentialsForNacosClient();
        assertEquals(ACCESS_KEY_ID, context.getAccessKey());
        assertEquals(ACCESS_KEY_SECRET, context.getSecretKey());
        assertEquals(SECURITY_TOKEN, context.getSecurityToken());
        assertEquals(SIGNATURE_REGION_ID, context.getExtensionSignatureRegionId());
    }
    
    @Test
    void getCredentialsForNacosClientWithoutSignatureRegionId() {
        injectProperties(properties);
        properties.remove(ExtensionAuthPropertyKey.SIGNATURE_REGION_ID.getKey());
        credentialsProvider.init(properties);
        ExtensionRamContext context = credentialsProvider.getCredentialsForNacosClient();
        assertEquals(ACCESS_KEY_ID, context.getAccessKey());
        assertEquals(ACCESS_KEY_SECRET, context.getSecretKey());
        assertEquals(SECURITY_TOKEN, context.getSecurityToken());
        assertNull(context.getExtensionSignatureRegionId());
    }
}