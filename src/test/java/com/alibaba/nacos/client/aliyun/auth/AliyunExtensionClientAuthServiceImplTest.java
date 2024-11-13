package com.alibaba.nacos.client.aliyun.auth;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.client.aliyun.auth.provider.ExtensionCredentialsProvider;
import com.alibaba.nacos.plugin.auth.api.LoginIdentityContext;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AliyunExtensionClientAuthServiceImplTest {
    
    AliyunExtensionClientAuthServiceImpl clientAuthService;
    
    RequestResource resource;
    
    @BeforeEach
    void setUp() {
        clientAuthService = new AliyunExtensionClientAuthServiceImpl();
        resource = RequestResource.configBuilder().build();
    }
    
    @AfterEach
    void tearDown() throws NacosException {
        clientAuthService.shutdown();
    }
    
    @Test
    void loginNoMatch() {
        assertFalse(clientAuthService.login(new Properties()));
    }
    
    @Test
    void loginWithException() {
        Properties properties = new Properties();
        properties.setProperty(ExtensionAuthPropertyKey.SECRET_NAME.getKey(), "secret");
        assertFalse(clientAuthService.login(properties));
    }
    
    @Test
    void loginSuccess() {
        Properties properties = new Properties();
        properties.setProperty(ExtensionAuthPropertyKey.SECURITY_TOKEN.getKey(), "securityToken");
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_ID.getKey(), "accessKeyId");
        properties.setProperty(ExtensionAuthPropertyKey.ACCESS_KEY_SECRET.getKey(), "accessKeySecret");
        assertTrue(clientAuthService.login(properties));
    }
    
    @Test
    void getLoginIdentityContextForStsToken() throws NoSuchFieldException, IllegalAccessException {
        injectMockProvider(true, true);
        LoginIdentityContext context = clientAuthService.getLoginIdentityContext(resource);
        assertEquals("accessKey", context.getParameter("Spas-AccessKey"));
        assertEquals("securityToken", context.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
        assertNotNull(context.getParameter("Spas-Signature"));
        assertNotNull(context.getParameter("Timestamp"));
    }
    
    @Test
    void getLoginIdentityContextForAkSk() throws NoSuchFieldException, IllegalAccessException {
        injectMockProvider(false, true);
        LoginIdentityContext context = clientAuthService.getLoginIdentityContext(resource);
        assertEquals("accessKey", context.getParameter("Spas-AccessKey"));
        assertNull(context.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
        assertNotNull(context.getParameter("Spas-Signature"));
        assertNotNull(context.getParameter("Timestamp"));
    }
    
    @Test
    void getLoginIdentityContextForStsTokenInvalid() throws NoSuchFieldException, IllegalAccessException {
        injectMockProvider(true, false);
        LoginIdentityContext context = clientAuthService.getLoginIdentityContext(resource);
        assertNull(context.getParameter("Spas-AccessKey"));
        assertNull(context.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
        assertNull(context.getParameter("Spas-Signature"));
        assertNull(context.getParameter("Timestamp"));
    }
    
    @Test
    void getLoginIdentityContextForAkSkInvalid() throws NoSuchFieldException, IllegalAccessException {
        injectMockProvider(false, false);
        LoginIdentityContext context = clientAuthService.getLoginIdentityContext(resource);
        assertNull(context.getParameter("Spas-AccessKey"));
        assertNull(context.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
        assertNull(context.getParameter("Spas-Signature"));
        assertNull(context.getParameter("Timestamp"));
    }
    
    @Test
    void getLoginIdentityContextForNoInjector() throws NoSuchFieldException, IllegalAccessException {
        injectMockProvider(true, true);
        resource.setType("Mock");
        LoginIdentityContext context = clientAuthService.getLoginIdentityContext(resource);
        assertNull(context.getParameter("Spas-AccessKey"));
        assertNull(context.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
        assertNull(context.getParameter("Spas-Signature"));
        assertNull(context.getParameter("Timestamp"));
    }
    
    @Test
    void getLoginIdentityContextWithoutInit() {
        LoginIdentityContext context = clientAuthService.getLoginIdentityContext(resource);
        assertNull(context.getParameter("Spas-AccessKey"));
        assertNull(context.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
        assertNull(context.getParameter("Spas-Signature"));
        assertNull(context.getParameter("Timestamp"));
    }
    
    private void injectMockProvider(boolean ephemeralAccessKeyId, boolean validate)
            throws NoSuchFieldException, IllegalAccessException {
        MockCredentialsProvider mockProvider = new MockCredentialsProvider();
        mockProvider.ephemeralAccessKeyId = ephemeralAccessKeyId;
        mockProvider.validate = validate;
        Field matchedProviderField = clientAuthService.getClass().getDeclaredField("matchedProvider");
        matchedProviderField.setAccessible(true);
        matchedProviderField.set(clientAuthService, mockProvider);
    }
    
    private static class MockCredentialsProvider implements ExtensionCredentialsProvider {
        
        boolean ephemeralAccessKeyId = true;
        
        boolean validate;
        
        @Override
        public boolean matchProvider(Properties properties) {
            return true;
        }
        
        @Override
        public void init(Properties properties) {
        }
        
        @Override
        public ExtensionRamContext getCredentialsForNacosClient() {
            ExtensionRamContext ramContext = new ExtensionRamContext();
            ramContext.setEphemeralAccessKeyId(ephemeralAccessKeyId);
            if (validate) {
                ramContext.setSecretKey("secretKey");
                ramContext.setAccessKey("accessKey");
                ramContext.setSecurityToken(ephemeralAccessKeyId ? "securityToken" : "");
            } else {
                ramContext.setSecurityToken(ephemeralAccessKeyId ? "" : "securityToken");
            }
            return ramContext;
        }
        
        @Override
        public void shutdown() throws NacosException {
        }
    }
}