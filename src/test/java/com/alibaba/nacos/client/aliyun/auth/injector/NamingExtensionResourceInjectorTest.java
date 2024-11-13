package com.alibaba.nacos.client.aliyun.auth.injector;

import com.alibaba.nacos.plugin.auth.api.RequestResource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NamingExtensionResourceInjectorTest {
    
    NamingExtensionResourceInjector resourceInjector;
    
    @BeforeEach
    void setUp() {
        resourceInjector = new NamingExtensionResourceInjector();
    }
    
    @AfterEach
    void tearDown() {
    }
    
    @Test
    void getAccessKeyHeaderKey() {
        assertEquals("ak", resourceInjector.getAccessKeyHeaderKey());
    }
    
    @Test
    void calculateSignatureWithoutGroup() {
        RequestResource resource = RequestResource.namingBuilder().setResource("TestService").build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.get("data").endsWith("TestService"));
        assertTrue(result.containsKey("signature"));
    }
    
    @Test
    void calculateSignatureWithGroup() {
        RequestResource resource = RequestResource.namingBuilder().setGroup("TestGroup").setResource("TestService")
                .build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.get("data").endsWith("TestGroup@@TestService"));
        assertTrue(result.containsKey("signature"));
    }
    
    @Test
    void calculateSignatureWithGroupedService() {
        RequestResource resource = RequestResource.namingBuilder().setResource("TestGroup@@TestService").build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.get("data").endsWith("TestGroup@@TestService"));
        assertTrue(result.containsKey("signature"));
    }
    
    @Test
    void calculateSignatureWithEmptyResource() {
        RequestResource resource = RequestResource.namingBuilder().setResource("").build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.get("data").matches("^\\d*$"));
        assertTrue(result.containsKey("signature"));
    }
    
    @Test
    void calculateSignatureWithException() {
        // Will Throw NPE.
        RequestResource resource = RequestResource.namingBuilder().build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(0, result.size());
    }
}