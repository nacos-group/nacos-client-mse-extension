package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.aliyun.credentials.Client;
import com.aliyun.credentials.models.CredentialModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
abstract class AbstractCredentialClientProviderTest extends AbstractCredentialsProviderTest {
    
    @Mock
    Client credentialsClient;
    
    protected CredentialModel credentialModel;
    
    @BeforeEach
    void setUp() {
        super.setUp();
        credentialModel = CredentialModel.builder().accessKeyId(ACCESS_KEY_ID).accessKeySecret(ACCESS_KEY_SECRET)
                .securityToken(SECURITY_TOKEN).build();
    }
    
    @Test
    void getCredentialsForNacosClient() throws NoSuchFieldException, IllegalAccessException {
        injectMockCredentialsClient();
        initWithProperties();
        mockCredentialsClientReturn(credentialModel);
        ExtensionRamContext context = getCredentialsProvider().getCredentialsForNacosClient();
        assertEquals(ACCESS_KEY_ID, context.getAccessKey());
        assertEquals(ACCESS_KEY_SECRET, context.getSecretKey());
        assertEquals(SECURITY_TOKEN, context.getSecurityToken());
    }
    
    @Test
    void getCredentialsForNacosClientByEnv() throws NoSuchFieldException, IllegalAccessException {
        injectMockCredentialsClient();
        initWithEnvProperties();
        mockCredentialsClientReturn(credentialModel);
        ExtensionRamContext context = getCredentialsProvider().getCredentialsForNacosClient();
        assertEquals(ACCESS_KEY_ID, context.getAccessKey());
        assertEquals(ACCESS_KEY_SECRET, context.getSecretKey());
        assertEquals(SECURITY_TOKEN, context.getSecurityToken());
    }
    
    @Test
    void getCredentialsForNacosClientWithoutInit() {
        ExtensionRamContext context = getCredentialsProvider().getCredentialsForNacosClient();
        assertNull(context.getAccessKey());
        assertNull(context.getSecretKey());
        assertNull(context.getSecurityToken());
    }
    
    protected void injectMockCredentialsClient() throws NoSuchFieldException, IllegalAccessException {
        Field clientField = credentialsProvider.getClass().getSuperclass().getDeclaredField("credentialsClient");
        clientField.setAccessible(true);
        clientField.set(credentialsProvider, credentialsClient);
    }
    
    protected void mockCredentialsClientReturn(CredentialModel credential)
            throws NoSuchFieldException, IllegalAccessException {
        when(credentialsClient.getCredential()).thenReturn(credential);
    }
    
    protected AbstractCredentialClientProvider getCredentialsProvider() {
        return (AbstractCredentialClientProvider) credentialsProvider;
    }
}