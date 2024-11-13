package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.exception.NacosException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractCredentialsProviderTest {
    
    protected static final String ACCESS_KEY_ID = "accessKeyId";
    
    protected static final String ACCESS_KEY_SECRET = "accessKeySecret";
    
    protected static final String SECURITY_TOKEN = "securityToken";
    
    protected static final String SIGNATURE_REGION_ID = "signatureRegionId";
    
    ExtensionCredentialsProvider credentialsProvider;
    
    Properties properties;
    
    @BeforeEach
    void setUp() {
        credentialsProvider = buildCredentialsProvider();
        properties = new Properties();
    }
    
    protected abstract ExtensionCredentialsProvider buildCredentialsProvider();
    
    @AfterEach
    void tearDown() throws NacosException {
        credentialsProvider.shutdown();
    }
    
    @Test
    void matchProvider() {
        assertFalse(credentialsProvider.matchProvider(properties));
        injectProperties(properties);
        assertTrue(credentialsProvider.matchProvider(properties));
    }
    
    protected void initWithProperties() {
        injectProperties(properties);
        credentialsProvider.init(properties);
    }
    
    protected void initWithEnvProperties() {
        injectEnvProperties(properties);
        credentialsProvider.init(properties);
    }
    
    protected abstract void injectProperties(Properties properties);
    
    protected abstract void injectEnvProperties(Properties properties);
}
