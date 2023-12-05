package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.config.filter.IConfigFilter;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.config.filter.impl.ConfigFilterChainManager;
import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import com.aliyuncs.exceptions.ClientException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
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

public class AliyunConfigFilterTest {
    private static final String ENCRYPTED_DATA_KEY = "encryptedDataKey";
    private static final String CONTENT = "content";
    public static Properties properties;
    public static final List<String> dataIdList = new ArrayList<String>(){{
        add("cipher-crypt");
        add("cipher-kms-aes-256-crypt");
        add("cipher-kms-aes-128-crypt");
    }};

    public static final String content = "crypt";

    public static final String group = "default";

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
        properties.setProperty("accessKey", "LTAxxxx1E6");
        properties.setProperty("secretKey", "kr6JxxxsD6");
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
    
    @Test
    public void testAliyunConfigFilterWithKmsV1UsingLocalCache()
            throws NoSuchFieldException, InvocationTargetException, IllegalAccessException, NoSuchMethodException {
        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv1.getValue());
        //ignore kmsEndpoint
        properties.setProperty("kmsEndpoint", "");
        properties.setProperty("regionId", "cn-beijing");
        properties.setProperty("kms_region_id", "cn-beijing");
        properties.setProperty("accessKey", "LTAxxx");
        properties.setProperty("secretKey", "EdPxxx");
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
    
    private void executeConfigFilterWithCacheAfterSet()
            throws NoSuchFieldException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        ConfigFilterChainManager configFilterChainManager = new ConfigFilterChainManager(properties);
        Class<? extends ConfigFilterChainManager> configFilterChainManagerClass =  configFilterChainManager.getClass();
        Field filtersField = configFilterChainManagerClass.getDeclaredField("filters");
        filtersField.setAccessible(true);
        List<IConfigFilter> filters = (List<IConfigFilter>) filtersField.get(configFilterChainManager);
        
        AliyunConfigFilter aliyunConfigFilter = (AliyunConfigFilter) filters.get(1);
        
        Class<AliyunConfigFilter> aliyunConfigFilterClass = AliyunConfigFilter.class;
        
        Method getGroupKey2 = aliyunConfigFilterClass.getDeclaredMethod("getGroupKey2", String.class, String.class);
        getGroupKey2.setAccessible(true);
        Field kmsLocalCacheField = aliyunConfigFilterClass.getDeclaredField("kmsLocalCache");
        kmsLocalCacheField.setAccessible(true);
        
        KmsLocalCache kmsLocalCache = (KmsLocalCache) kmsLocalCacheField.get(aliyunConfigFilter);
        
        for (String dataId : dataIdList) {
            String groupKey = (String) getGroupKey2.invoke(aliyunConfigFilter, dataId, group);
            kmsLocalCache.remove(groupKey);
            ConfigRequest configRequest = new ConfigRequest();
            configRequest.setGroup(group);
            configRequest.setDataId(dataId);
            configRequest.setContent(content);
            try {
                configFilterChainManager.doFilter(configRequest, null);
                KmsLocalCache.LocalCacheItem localCacheItem = kmsLocalCache.get(groupKey);
                if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getEncryptedContent(), configRequest.getContent());
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configRequest.getEncryptedDataKey());
                } else if (dataId.startsWith(CIPHER_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getEncryptedContent(), configRequest.getContent());
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
                    Assertions.assertEquals(localCacheItem.getEncryptedContent(), configRequest.getContent());
                    Assertions.assertEquals(localCacheItem.getEncryptedDataKey(), configRequest.getEncryptedDataKey());
                    Assertions.assertEquals(content, configResponse.getContent());
                } else if (dataId.startsWith(CIPHER_PREFIX)) {
                    Assertions.assertEquals(localCacheItem.getPlainContent(), configResponse.getContent());
                }
            } catch (NacosException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void executeConfigFilter() {
       ConfigFilterChainManager configFilterChainManager = new ConfigFilterChainManager(properties);
       AliyunConfigFilter aliyunConfigFilter = new AliyunConfigFilter();
       configFilterChainManager.addFilter(aliyunConfigFilter);
        
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
}
