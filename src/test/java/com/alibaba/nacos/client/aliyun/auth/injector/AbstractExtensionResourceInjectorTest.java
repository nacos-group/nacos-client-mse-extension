package com.alibaba.nacos.client.aliyun.auth.injector;

import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthConstants;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.alibaba.nacos.plugin.auth.api.LoginIdentityContext;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class AbstractExtensionResourceInjectorTest {
    
    AbstractExtensionResourceInjector resourceInjector;
    
    ExtensionRamContext ramContext;
    
    RequestResource resource;
    
    @BeforeEach
    void setUp() {
        resourceInjector = new MockExtensionResourceInjector();
        ramContext = new ExtensionRamContext();
        ramContext.setSecretKey("secret");
        ramContext.setEphemeralAccessKeyId(false);
        resource = new RequestResource();
    }
    
    @AfterEach
    void tearDown() {
    }
    
    @Test
    void doInjectForV4WithoutRegionId() {
        LoginIdentityContext result = new LoginIdentityContext();
        resourceInjector.doInject(resource, ramContext, result);
        assertEquals("secret", result.getParameter("sk"));
        assertNull(result.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
    }
    
    @Test
    void doInjectForV4WithRegionId() {
        ramContext.setExtensionSignatureRegionId("cn-hangzhou");
        LoginIdentityContext result = new LoginIdentityContext();
        resourceInjector.doInject(resource, ramContext, result);
        assertNotEquals("secret", result.getParameter("sk"));
        assertNull(result.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
    }
    
    @Test
    void doInjectForV4WithRegionIdAndStsToken() {
        ramContext.setExtensionSignatureRegionId("cn-hangzhou");
        ramContext.setSecurityToken("token");
        ramContext.setEphemeralAccessKeyId(true);
        LoginIdentityContext result = new LoginIdentityContext();
        resourceInjector.doInject(resource, ramContext, result);
        assertNotEquals("secret", result.getParameter("sk"));
        assertEquals("token", result.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
    }
    
    @Test
    void doInjectForV1WithRegionId() throws NoSuchFieldException, IllegalAccessException {
        Field supportV4signatureField = resourceInjector.getClass().getSuperclass()
                .getDeclaredField("supportV4signature");
        supportV4signatureField.setAccessible(true);
        supportV4signatureField.set(resourceInjector, false);
        ramContext.setExtensionSignatureRegionId("cn-hangzhou");
        LoginIdentityContext result = new LoginIdentityContext();
        resourceInjector.doInject(resource, ramContext, result);
        assertEquals("secret", result.getParameter("sk"));
        assertNull(result.getParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER));
    }
    
    private static class MockExtensionResourceInjector extends AbstractExtensionResourceInjector {
        
        @Override
        protected String getAccessKeyHeaderKey() {
            return "Mock";
        }
        
        @Override
        protected Map<String, String> calculateSignature(RequestResource resource, String actualSecretKey,
                ExtensionRamContext ramContext) {
            return Collections.singletonMap("sk", actualSecretKey);
        }
    }
}