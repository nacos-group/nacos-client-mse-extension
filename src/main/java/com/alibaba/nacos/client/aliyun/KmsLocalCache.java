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
        if (StringUtils.isBlank(key)) {
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
        if (StringUtils.isBlank(key) || localCacheItem == null) {
            return;
        }
        try {
            encryptedContentCache.put(key, localCacheItem);
        } catch (Exception e) {
            LOGGER.error("put encrypted content to local cache failed, key: {}", key, e);
        }
    }
    
    public void remove(String key) {
        if (StringUtils.isBlank(key)) {
            return;
        }
        this.encryptedContentCache.invalidate(key);
    }
    
    public static class LocalCacheItem {
        private final String encryptedDataKey;
        
        private final String encryptedContent;
        
        private final String encryptedContentMD5;
        
        private final String plainDataKey;
        
        private final String plainContent;
        
        public LocalCacheItem(String encryptedDataKey, String encryptedContent, String plainDataKey) {
            this.encryptedDataKey = encryptedDataKey;
            this.plainDataKey = plainDataKey;
            this.encryptedContent = null;
            this.encryptedContentMD5 = MD5Utils.md5Hex(encryptedContent, AliyunConst.ENCODE_UTF8);
            this.plainContent = null;
        }
        
        public LocalCacheItem(String encryptedContent, String plainContent) {
            this.encryptedDataKey = null;
            this.plainDataKey = null;
            this.encryptedContent = null;
            this.encryptedContentMD5 = MD5Utils.md5Hex(encryptedContent, AliyunConst.ENCODE_UTF8);
            this.plainContent = plainContent;
        }
        
        public String getEncryptedDataKey() {
            return encryptedDataKey;
        }
        
        public String getEncryptedContent() {
            return encryptedContent;
        }
        
        public String getPlainDataKey() {
            return plainDataKey;
        }
        
        public String getPlainContent() {
            return plainContent;
        }
        
        public String getEncryptedContentMD5() {
            return encryptedContentMD5;
        }
        
        @Override
        public String toString() {
            return "LocalCacheItem{" + "encryptedDataKey='" + encryptedDataKey + '\'' + ", encryptedContent='"
                    + encryptedContent + '\'' + ", encryptedContentMD5='" + encryptedContentMD5 + '\''
                    + ", plainDataKey='" + plainDataKey + '\'' + ", plainContent='" + plainContent + '\'' + '}';
        }
    }
}
