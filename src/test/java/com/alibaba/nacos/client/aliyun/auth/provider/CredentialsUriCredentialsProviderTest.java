package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.aliyun.credentials.models.Config;
import com.aliyun.credentials.models.CredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class CredentialsUriCredentialsProviderTest extends AbstractCredentialClientProviderTest {
    
    @Override
    protected ExtensionCredentialsProvider buildCredentialsProvider() {
        return new CredentialsUriCredentialsProvider();
    }
    
    @Override
    protected void injectProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.CREDENTIALS_URI.getKey(), "http://localhost");
    }
    
    @Override
    protected void injectEnvProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.CREDENTIALS_URI.getEnvKey(), "http://envhost");
    }
    
    @Test
    void generateCredentialsConfig() {
        initWithProperties();
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("credentials_uri", config.getType());
        assertEquals("http://localhost", config.getCredentialsUri());
    }
    
    @Test
    void generateCredentialsConfigByEnv() {
        initWithEnvProperties();
        Config config = getCredentialsProvider().generateCredentialsConfig(properties);
        assertEquals("credentials_uri", config.getType());
        assertEquals("http://envhost", config.getCredentialsUri());
    }
}