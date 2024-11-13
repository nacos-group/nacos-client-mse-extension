package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.exception.runtime.NacosRuntimeException;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.aliyuncs.kms.secretsmanager.client.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.model.SecretInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AutoRotateCredentialsProviderTest extends AbstractCredentialsProviderTest {
    
    @Mock
    private SecretCacheClient client;
    
    @Override
    protected ExtensionCredentialsProvider buildCredentialsProvider() {
        return new AutoRotateCredentialsProvider();
    }
    
    @Override
    protected void injectProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.SECRET_NAME.getKey(), "secretName");
    }
    
    @Override
    protected void injectEnvProperties(Properties properties) {
        properties.setProperty(ExtensionAuthPropertyKey.SECRET_NAME.getEnvKey(), "secretName");
        
    }
    
    @Test
    void testInitWithException() {
        assertThrows(NacosRuntimeException.class, this::initWithProperties);
    }
    
    @Test
    void getCredentialsForNacosClient() throws NoSuchFieldException, IllegalAccessException, CacheSecretException {
        setClient();
        initWithProperties();
        ExtensionRamContext result = credentialsProvider.getCredentialsForNacosClient();
        assertEquals("accessKeyId", result.getAccessKey());
        assertEquals("accessKeySecret", result.getSecretKey());
        assertFalse(result.isEphemeralAccessKeyId());
    }
    
    @Test
    void getCredentialsForNacosClientByEnv() throws NoSuchFieldException, IllegalAccessException, CacheSecretException {
        setClient();
        initWithEnvProperties();
        ExtensionRamContext result = credentialsProvider.getCredentialsForNacosClient();
        assertEquals("accessKeyId", result.getAccessKey());
        assertEquals("accessKeySecret", result.getSecretKey());
        assertFalse(result.isEphemeralAccessKeyId());
    }
    
    @Test
    void getCredentialsForNacosClientWithException()
            throws NoSuchFieldException, IllegalAccessException, CacheSecretException {
        setClient();
        when(client.getSecretInfo("secretName")).thenThrow(new CacheSecretException());
        initWithEnvProperties();
        ExtensionRamContext result = credentialsProvider.getCredentialsForNacosClient();
        assertNull(result.getAccessKey());
        assertNull(result.getSecretKey());
        assertFalse(result.isEphemeralAccessKeyId());
    }
    
    @Test
    void getCredentialsForNacosClientWithoutInit() {
        ExtensionRamContext result = credentialsProvider.getCredentialsForNacosClient();
        assertNull(result.getAccessKey());
        assertNull(result.getSecretKey());
        assertFalse(result.isEphemeralAccessKeyId());
    }
    
    private void setClient() throws NoSuchFieldException, IllegalAccessException, CacheSecretException {
        Field clientField = credentialsProvider.getClass().getDeclaredField("client");
        clientField.setAccessible(true);
        clientField.set(credentialsProvider, client);
        SecretInfo secretInfo = new SecretInfo();
        secretInfo.setSecretValue("{\"AccessKeyId\":\"accessKeyId\",\"AccessKeySecret\":\"accessKeySecret\"}");
        when(client.getSecretInfo("secretName")).thenReturn(secretInfo);
    }
}