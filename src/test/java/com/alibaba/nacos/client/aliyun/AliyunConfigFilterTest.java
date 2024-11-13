package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.config.filter.IConfigFilter;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.config.filter.impl.ConfigFilterChainManager;
import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_128_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_256_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.ENCODE_UTF8;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KMS_DEFAULT_KEY_ID_VALUE;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KMS_KEY_SPEC_AES_256;

@Disabled("This unit test depend accessKey to request KMS, default disabled")
public class AliyunConfigFilterTest {
    private static final String ENCRYPTED_DATA_KEY = "encryptedDataKey";
    private static final String CONTENT = "content";
    public static Properties properties;
    public static final List<String> dataIdList = new ArrayList<String>(){{
        add("cipher-crypt");
        add("cipher-kms-aes-256-crypt");
        add("cipher-kms-aes-128-crypt");
    }};

    public static final String content = "crypt中文&&";

    public static final String group = "default";
    
    public static final String ak = "LTAIxxx";
    
    public static final String sk = "EdPqxxx";
    @BeforeEach
    public void preset() {
        try {
            properties = new Properties();
            properties.load(this.getClass().getResourceAsStream("/aliyun-kms.properties"));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testAliyunConfigFilterWithKmsV1() {
        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv1.getValue());
        //ignore kmsEndpoint
        properties.setProperty("kmsEndpoint", "");
        properties.setProperty("regionId", "cn-beijing");
        properties.setProperty("kms_region_id", "cn-beijing");
        properties.setProperty("accessKey", ak);
        properties.setProperty("secretKey", sk);
        properties.setProperty("keyId", "alias/acs/mse");
        executeConfigFilter();
    }

    // must be running in vpc
//    @Test
//    public void testAliyunConfigFilterWithKmsV3() {
//        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv3.getValue());
//        properties.setProperty("keyId", "alias/chasu");
//        properties.setProperty("kmsEndpoint", "kst-bjxxxxxxxxxc.cryptoservice.kms.aliyuncs.com");
//        properties.setProperty("kmsClientKeyFilePath", "/client_key.json");
//        properties.setProperty("kmsPasswordKey", "19axxx213");
//        properties.setProperty("kmsCaFilePath", "/ca.pem");
//        executeConfigFilter();
//    }
    
    @Test
    public void testAliyunConfigFilterWithKmsV1UsingLocalCache()
            throws NoSuchFieldException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv1.getValue());
        //ignore kmsEndpoint
        properties.setProperty("kmsEndpoint", "");
        properties.setProperty("regionId", "cn-beijing");
        properties.setProperty("kms_region_id", "cn-beijing");
        properties.setProperty("accessKey", ak);
        properties.setProperty("secretKey", sk);
        properties.setProperty("keyId", "alias/acs/mse");
        executeConfigFilterWithCacheAfterSet();
    }
    
    // must be running in vpc
    //    @Test
    //    public void testAliyunConfigFilterWithKmsV3UsingLocalCache() {
    //        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv3.getValue());
    //        properties.setProperty("keyId", "alias/chasu");
    //        properties.setProperty("kmsEndpoint", "kst-bjxxxxxxxxxc.cryptoservice.kms.aliyuncs.com");
    //        properties.setProperty("kmsClientKeyFilePath", "/client_key.json");
    //        properties.setProperty("kmsPasswordKey", "19axxx213");
    //        properties.setProperty("kmsCaFilePath", "/ca.pem");
    //        executeConfigFilterWithCacheAfterSet();
    //    }
    
    @Test
    public void testAliyunConfigFilterEncryptIdempotentOfTheSameConfig() throws Exception {
        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv1.getValue());
        //ignore kmsEndpoint
        properties.setProperty("kmsEndpoint", "");
        properties.setProperty("regionId", "cn-beijing");
        properties.setProperty("kms_region_id", "cn-beijing");
        properties.setProperty("accessKey", ak);
        properties.setProperty("secretKey", sk);
        properties.setProperty("keyId", "alias/acs/mse");
        properties.setProperty(AliyunConst.NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_SWITCH, "false");
        verifyEncryptedConfigByKmsIdempotent();
    }
    
    @Test
    public void testLocallyRunWithRetryTimesAndTimeout()
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        Class<AliyunConfigFilter> aliyunConfigFilterClass = AliyunConfigFilter.class;
        Method locallyRunWithRetryTimesAndTimeout = aliyunConfigFilterClass.getDeclaredMethod(
                "locallyRunWithRetryTimesAndTimeout", Supplier.class, int.class, long.class);
        locallyRunWithRetryTimesAndTimeout.setAccessible(true);
        AliyunConfigFilter aliyunConfigFilter = new AliyunConfigFilter();
        
        //return false to retry with defaultRetryTimes
        AtomicInteger atomicInteger = new AtomicInteger(0);
        locallyRunWithRetryTimesAndTimeout.invoke(aliyunConfigFilter, new Supplier<Boolean>() {
            @Override
            public Boolean get() {
                atomicInteger.incrementAndGet();
                return false;
            }
        }, AliyunConfigFilter.defaultRetryTimes, AliyunConfigFilter.defaultTimeoutMilliseconds);
        Assertions.assertEquals(AliyunConfigFilter.defaultRetryTimes, atomicInteger.get());
        
        //return false to retry with timeout
        atomicInteger.set(0);
        locallyRunWithRetryTimesAndTimeout.invoke(aliyunConfigFilter, new Supplier<Boolean>() {
            @Override
            public Boolean get() {
                atomicInteger.incrementAndGet();
                try {
                    Thread.sleep(AliyunConfigFilter.defaultTimeoutMilliseconds);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                return false;
            }
        }, AliyunConfigFilter.defaultRetryTimes, AliyunConfigFilter.defaultTimeoutMilliseconds);
        Assertions.assertEquals(1, atomicInteger.get());
        
        //return false to retry with expectedException
        atomicInteger.set(0);
        locallyRunWithRetryTimesAndTimeout.invoke(aliyunConfigFilter, new Supplier<Boolean>() {
            @Override
            public Boolean get() {
                atomicInteger.incrementAndGet();
                if (atomicInteger.get() == 1) {
                    return !KmsUtils.judgeNeedRecoveryException(new ClientException(KmsUtils.REJECTED_THROTTLING, "error message"));
                } else if (atomicInteger.get() == 2) {
                    return !KmsUtils.judgeNeedRecoveryException(new ClientException(KmsUtils.SERVICE_UNAVAILABLE_TEMPORARY, "error message"));
                } else if (atomicInteger.get() == 3) {
                    return !KmsUtils.judgeNeedRecoveryException(new ClientException(KmsUtils.INTERNAL_FAILURE, "error message"));
                } else if (atomicInteger.get() == 4) {
                    return !KmsUtils.judgeNeedRecoveryException(new ClientException(KmsUtils.SDK_READ_TIMEOUT, "error message"));
                } else if (atomicInteger.get() == 5) {
                    return !KmsUtils.judgeNeedRecoveryException(new ClientException(KmsUtils.SDK_SERVER_UNREACHABLE, "error message"));
                } else {
                    return true;
                }
            }
        }, 10, AliyunConfigFilter.defaultTimeoutMilliseconds);
        Assertions.assertEquals(6, atomicInteger.get());
    }
    
    
    private void executeConfigFilterWithCacheAfterSet()
            throws NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        ConfigFilterChainManager configFilterChainManager = new ConfigFilterChainManager(properties);
        Class<? extends ConfigFilterChainManager> configFilterChainManagerClass =  configFilterChainManager.getClass();
        Field filtersField = configFilterChainManagerClass.getDeclaredField("filters");
        filtersField.setAccessible(true);
        List<IConfigFilter> filters = (List<IConfigFilter>) filtersField.get(configFilterChainManager);
        
        AliyunConfigFilter aliyunConfigFilter = (AliyunConfigFilter) filters.get(1);
        
        Class<AliyunConfigFilter> aliyunConfigFilterClass = AliyunConfigFilter.class;
        
        Field kmsLocalCacheField = aliyunConfigFilterClass.getDeclaredField("kmsLocalCache");
        kmsLocalCacheField.setAccessible(true);
        
        KmsLocalCache kmsLocalCache = (KmsLocalCache) kmsLocalCacheField.get(aliyunConfigFilter);
        
        for (String dataId : dataIdList) {
            String groupKey = GroupKeyUtils.getGroupKey2(dataId, group);
            kmsLocalCache.remove(groupKey);
            ConfigRequest configRequest = new ConfigRequest();
            configRequest.setGroup(group);
            configRequest.setDataId(dataId);
            configRequest.setContent(content);
            try {
                configFilterChainManager.doFilter(configRequest, null);
                KmsLocalCache.LocalCacheItem localCacheItem = kmsLocalCache.get(groupKey);
                if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getEncryptedContentMD5(), MD5Utils.md5Hex(configRequest.getContent(), ENCODE_UTF8));
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configRequest.getEncryptedDataKey());
                } else if (dataId.startsWith(CIPHER_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getEncryptedContentMD5(), MD5Utils.md5Hex(configRequest.getContent(), ENCODE_UTF8));
                    Assertions.assertEquals(localCacheItem.getPlainContent(), content);
                }
            } catch (NacosException e) {
                e.printStackTrace();
            }
            
            ConfigResponse configResponse = new ConfigResponse();
            configResponse.setGroup(group);
            configResponse.setDataId(dataId);
            configResponse.setEncryptedDataKey((String) configRequest.getParameter(ENCRYPTED_DATA_KEY));
            configResponse.setContent((String) configRequest.getParameter(CONTENT));
            kmsLocalCache.remove(groupKey);
            try {
                configFilterChainManager.doFilter(null, configResponse);
                KmsLocalCache.LocalCacheItem localCacheItem = kmsLocalCache.get(groupKey);
                if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getEncryptedContentMD5(), MD5Utils.md5Hex(configRequest.getContent(), ENCODE_UTF8));
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configRequest.getEncryptedDataKey());
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configResponse.getEncryptedDataKey());
                } else if (dataId.startsWith(CIPHER_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getPlainContent(), configResponse.getContent());
                    Assertions.assertEquals(localCacheItem.getEncryptedContentMD5(), MD5Utils.md5Hex(configRequest.getContent(), ENCODE_UTF8));
                }
                Assertions.assertEquals(content, configResponse.getContent());
            } catch (NacosException e) {
                throw new RuntimeException(e);
            }
            
            Field localCacheTestModeField = aliyunConfigFilterClass.getDeclaredField("localCacheTestMode");
            localCacheTestModeField.setAccessible(true);
            localCacheTestModeField.set(aliyunConfigFilter, true);
            ConfigResponse configResponse1 = new ConfigResponse();
            configResponse1.setGroup(group);
            configResponse1.setDataId(dataId);
            configResponse1.setEncryptedDataKey((String) configRequest.getParameter(ENCRYPTED_DATA_KEY));
            configResponse1.setContent((String) configRequest.getParameter(CONTENT));
            
            try {
                configFilterChainManager.doFilter(null, configResponse1);
                KmsLocalCache.LocalCacheItem localCacheItem = kmsLocalCache.get(groupKey);
                if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getEncryptedContentMD5(), MD5Utils.md5Hex(configRequest.getContent(), ENCODE_UTF8));
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configRequest.getEncryptedDataKey());
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configResponse1.getEncryptedDataKey());
                } else if (dataId.startsWith(CIPHER_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getPlainContent(), configResponse1.getContent());
                    Assertions.assertEquals(localCacheItem.getEncryptedContentMD5(), MD5Utils.md5Hex(configRequest.getContent(), ENCODE_UTF8));
                }
                Assertions.assertEquals(content, configResponse1.getContent());
            } catch (NacosException e) {
                throw new RuntimeException(e);
            } finally {
                localCacheTestModeField.set(aliyunConfigFilter, false);
            }
        }
    }

    private void executeConfigFilter() {
       ConfigFilterChainManager configFilterChainManager = new ConfigFilterChainManager(properties);
        
        for (String dataId : dataIdList) {
            ConfigRequest configRequest = new ConfigRequest();
            configRequest.setGroup(group);
            configRequest.setDataId(dataId);
            configRequest.setContent(content);
            String encryptedContent = null;
            try {
                configFilterChainManager.doFilter(configRequest, null);
                encryptedContent = configRequest.getContent();
                Assertions.assertFalse(StringUtils.isBlank(encryptedContent));
            } catch (NacosException e) {
                e.printStackTrace();
            }

            ConfigResponse configResponse = new ConfigResponse();
            configResponse.setGroup(group);
            configResponse.setDataId(dataId);
            configResponse.setEncryptedDataKey((String) configRequest.getParameter(ENCRYPTED_DATA_KEY));
            configResponse.setContent(encryptedContent);
            try {
                configFilterChainManager.doFilter(null, configResponse);
                Assertions.assertEquals(content, configResponse.getContent());
            } catch (NacosException e) {
                throw new RuntimeException(e);
            }
        }
    }
    
    private void verifyEncryptedConfigByKmsIdempotent() throws Exception {
        ConfigFilterChainManager configFilterChainManager = new ConfigFilterChainManager(properties);
        
        String dataId = "cipher-crypt";
        ConfigRequest configRequest = new ConfigRequest();
        configRequest.setGroup(group);
        configRequest.setDataId(dataId);
        configRequest.setContent(content);
        ConfigRequest configRequest1 = new ConfigRequest();
        configRequest1.setGroup(group);
        configRequest1.setDataId(dataId);
        configRequest1.setContent(content);
        String encryptedContent;
        String encryptedContent1;
        try {
            configFilterChainManager.doFilter(configRequest, null);
            configFilterChainManager.doFilter(configRequest1, null);
            encryptedContent = configRequest.getContent();
            encryptedContent1 = configRequest1.getContent();
            Assertions.assertNotEquals(encryptedContent, encryptedContent1);
        } catch (NacosException e) {
            e.printStackTrace();
        }
        
        Class<? extends ConfigFilterChainManager> configFilterChainManagerClass =  configFilterChainManager.getClass();
        Field filtersField = configFilterChainManagerClass.getDeclaredField("filters");
        filtersField.setAccessible(true);
        List<IConfigFilter> filters = (List<IConfigFilter>) filtersField.get(configFilterChainManager);
        
        AliyunConfigFilter aliyunConfigFilter = (AliyunConfigFilter) filters.get(1);
        
        GenerateDataKeyResponse generateDataKeyResponse = aliyunConfigFilter.generateDataKey(KMS_DEFAULT_KEY_ID_VALUE,
                KMS_KEY_SPEC_AES_256);
        GenerateDataKeyResponse generateDataKeyResponse1 = aliyunConfigFilter.generateDataKey(KMS_DEFAULT_KEY_ID_VALUE,
                KMS_KEY_SPEC_AES_256);
        
        Assertions.assertNotEquals(generateDataKeyResponse1.getPlaintext(), generateDataKeyResponse.getPlaintext());
        
        Assertions.assertNotEquals(
                AesUtils.encrypt(content, generateDataKeyResponse.getPlaintext(), ENCODE_UTF8),
                AesUtils.encrypt(content, generateDataKeyResponse1.getPlaintext(), ENCODE_UTF8));
        
        Assertions.assertEquals(
                AesUtils.encrypt(content, generateDataKeyResponse.getPlaintext(), ENCODE_UTF8),
                AesUtils.encrypt(content, generateDataKeyResponse.getPlaintext(), ENCODE_UTF8));
        
    }
}
