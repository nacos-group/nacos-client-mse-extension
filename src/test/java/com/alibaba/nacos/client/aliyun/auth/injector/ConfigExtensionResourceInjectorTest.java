package com.alibaba.nacos.client.aliyun.auth.injector;

import com.alibaba.nacos.client.auth.ram.utils.SpasAdapter;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfigExtensionResourceInjectorTest {
    
    ConfigExtensionResourceInjector resourceInjector;
    
    @BeforeEach
    void setUp() {
        resourceInjector = new ConfigExtensionResourceInjector();
    }
    
    @AfterEach
    void tearDown() {
    }
    
    @Test
    void getAccessKeyHeaderKey() {
        assertEquals("Spas-AccessKey", resourceInjector.getAccessKeyHeaderKey());
    }
    
    @Test
    void calculateSignatureWithTenant() {
        RequestResource resource = RequestResource.configBuilder().setNamespace("TestNamespace").build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("Timestamp"));
        String expected = SpasAdapter.signWithHmacSha1Encrypt("TestNamespace+" + result.get("Timestamp"), "secret");
        assertEquals(expected, result.get("Spas-Signature"));
    }
    
    @Test
    void calculateSignatureWithGroup() {
        RequestResource resource = RequestResource.namingBuilder().setGroup("TestGroup").build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("Timestamp"));
        String expected = SpasAdapter.signWithHmacSha1Encrypt("TestGroup+" + result.get("Timestamp"), "secret");
        assertEquals(expected, result.get("Spas-Signature"));
    }
    
    @Test
    void calculateSignatureWithAll() {
        RequestResource resource = RequestResource.namingBuilder().setGroup("TestGroup").setNamespace("TestNamespace")
                .build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("Timestamp"));
        String expected = SpasAdapter.signWithHmacSha1Encrypt("TestNamespace+TestGroup+" + result.get("Timestamp"),
                "secret");
        assertEquals(expected, result.get("Spas-Signature"));
    }
    
    @Test
    void calculateSignatureWithEmptyResource() {
        RequestResource resource = RequestResource.namingBuilder().setResource("").build();
        Map<String, String> result = resourceInjector.calculateSignature(resource, "secret", null);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("Timestamp"));
        String expected = SpasAdapter.signWithHmacSha1Encrypt(result.get("Timestamp"), "secret");
        assertEquals(expected, result.get("Spas-Signature"));
    }
    
    @Test
    void calculateSignatureWithException() {
        // Will Throw NPE.
        Map<String, String> result = resourceInjector.calculateSignature(null, "secret", null);
        assertEquals(0, result.size());
    }
}