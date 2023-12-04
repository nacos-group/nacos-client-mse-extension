package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.utils.StringUtils;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static com.alibaba.nacos.client.aliyun.AliyunConst.DEFAULT_KMS_LOCAL_CACHE_MAX_SIZE;

/**
 * @author rong
 */
public class KmsLocalCache {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(KmsLocalCache.class);
    
    private final Cache<String, LocalCacheItem> encryptedContentCache;
    
    KmsLocalCache(Properties properties) {
        int cacheSize = KmsUtils.parsePropertyValue(properties,
                AliyunConst.NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_SIZE, DEFAULT_KMS_LOCAL_CACHE_MAX_SIZE);
        int afterAccessDurationSeconds = KmsUtils.parsePropertyValue(properties,
                AliyunConst.NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_AFTER_ACCESS_DURATION, AliyunConst.DEFAULT_KMS_LOCAL_CACHE_AFTER_ACCESS_DURATION_SECONDS);
        int afterWriteDurationSeconds = KmsUtils.parsePropertyValue(properties,
                AliyunConst.NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_AFTER_WRITE_DURATION, AliyunConst.DEFAULT_KMS_LOCAL_CACHE_AFTER_WRITE_DURATION_SECONDS);
        encryptedContentCache = CacheBuilder.newBuilder().maximumSize(cacheSize)
                .expireAfterAccess(afterAccessDurationSeconds, TimeUnit.SECONDS)
                .expireAfterWrite(afterWriteDurationSeconds, TimeUnit.SECONDS).build();
    }
    
    public LocalCacheItem get(String key) {
        if (StringUtils.isEmpty(key)) {
            return null;
        }
        try {
            return encryptedContentCache.getIfPresent(key);
        } catch (Exception e) {
            LOGGER.error("get encrypted content from local cache failed, key: {}", key, e);
            return null;
        }
    }
    
    public void put(String key, LocalCacheItem localCacheItem) {
        if (StringUtils.isEmpty(key) || localCacheItem == null) {
            return;
        }
        try {
            encryptedContentCache.put(key, localCacheItem);
        } catch (Exception e) {
            LOGGER.error("put encrypted content to local cache failed, key: {}", key, e);
        }
    }
    
    public void remove(String key) {
        if (StringUtils.isEmpty(key)) {
            return;
        }
        this.encryptedContentCache.invalidate(key);
    }
    
    public static class LocalCacheItem {
        private String encryptedDataKey;
        
        private String encryptedContent;
        
        private String plainContent;
        
        public LocalCacheItem() {}
        
        public LocalCacheItem(String encryptedDataKey, String encryptedContent, String plainContent) {
            this.encryptedDataKey = encryptedDataKey;
            this.encryptedContent = encryptedContent;
            this.plainContent = plainContent;
        }
        
        public String getEncryptedDataKey() {
            return encryptedDataKey;
        }
        
        public void setEncryptedDataKey(String encryptedDataKey) {
            this.encryptedDataKey = encryptedDataKey;
        }
        
        public String getEncryptedContent() {
            return encryptedContent;
        }
        
        public void setEncryptedContent(String encryptedContent) {
            this.encryptedContent = encryptedContent;
        }
        
        public String getPlainContent() {
            return plainContent;
        }
        
        public void setPlainContent(String plainContent) {
            this.plainContent = plainContent;
        }
        
        @Override
        public String toString() {
            return "LocalCacheItem{" + "encryptedDataKey='" + encryptedDataKey + '\'' + ", encryptedContent='"
                    + encryptedContent + '\'' + ", plainContent='" + plainContent + '\'' + '}';
        }
    }
}
