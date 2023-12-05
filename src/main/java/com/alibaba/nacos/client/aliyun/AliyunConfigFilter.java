package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.config.filter.AbstractConfigFilter;
import com.alibaba.nacos.api.config.filter.IConfigFilterChain;
import com.alibaba.nacos.api.config.filter.IConfigRequest;
import com.alibaba.nacos.api.config.filter.IConfigResponse;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyun.dkms.gcs.openapi.models.Config;
import com.aliyun.kms.KmsTransferAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.auth.AlibabaCloudCredentialsProvider;
import com.aliyuncs.auth.InstanceProfileCredentialsProvider;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.HttpClientConfig;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.DecryptRequest;
import com.aliyuncs.kms.model.v20160120.DescribeKeyRequest;
import com.aliyuncs.kms.model.v20160120.DescribeKeyResponse;
import com.aliyuncs.kms.model.v20160120.EncryptRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import com.aliyuncs.kms.model.v20160120.SetDeletionProtectionRequest;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_128_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_KMS_AES_256_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CIPHER_PREFIX;
import static com.alibaba.nacos.client.aliyun.AliyunConst.CONTENT;
import static com.alibaba.nacos.client.aliyun.AliyunConst.DATA_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.ENCRYPTED_DATA_KEY;
import static com.alibaba.nacos.client.aliyun.AliyunConst.GROUP;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KEY_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KMS_KEY_SPEC_AES_128;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KMS_KEY_SPEC_AES_256;
import static com.alibaba.nacos.client.aliyun.AliyunConst.KMS_REGION_ID;
import static com.alibaba.nacos.client.aliyun.AliyunConst.REGION_ID;

/**
 * the IConfigFilter of Aliyun.
 *
 * @author luyanbo(RobberPhex)
 */
public class AliyunConfigFilter extends AbstractConfigFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AliyunConfigFilter.class);

    public static final int defaultRetryTimes = 3;
    
    public static final int defaultRetryIntervalMilliseconds = 2 * 100;
    
    public static final int defaultTimeoutMilliseconds = 3 * 1000;
    
    private AliyunConst.KmsVersion kmsVersion;
    
    private IAcsClient kmsClient;

    private String keyId;

    private final Set<String> addedKeys = new HashSet<String>();

    private AsyncProcessor asyncProcessor;

    private Exception localInitException;
    
    private boolean isUseLocalCache;
    
    private KmsLocalCache kmsLocalCache;

    @Override
    public void init(Properties properties) {
        LOGGER.info("init ConfigFilter: {}, for more information, please check: {}",
                this.getFilterName(), AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
        // get kms version, default using kms v1
        String kv = properties.getProperty(AliyunConst.KMS_VERSION_KEY,
                System.getProperty(AliyunConst.KMS_VERSION_KEY, System.getenv(AliyunConst.KMS_VERSION_KEY)));
        if (StringUtils.isBlank(kv)) {
            LOGGER.warn("kms version is not set, using kms v1 version.");
            kmsVersion = AliyunConst.KmsVersion.Kmsv1;
        } else {
            kmsVersion = AliyunConst.KmsVersion.fromValue(kv);
            if (kmsVersion == AliyunConst.KmsVersion.UNKNOWN_VERSION) {
                LOGGER.warn("kms version is not supported, using kms v1 version.");
                kmsVersion = AliyunConst.KmsVersion.Kmsv1;
            } else {
                LOGGER.info("using kms version {}.", kmsVersion.getValue());
            }
        }

        //keyId corresponding to the id/alias of KMS's secret key, using mseServiceKeyId by default
        keyId = properties.getProperty(KEY_ID, System.getProperty(KEY_ID, System.getenv(KEY_ID)));
        if (StringUtils.isBlank(keyId)) {
            if (kmsVersion == AliyunConst.KmsVersion.Kmsv1) {
                keyId = AliyunConst.KMS_DEFAULT_KEY_ID_VALUE;
                LOGGER.info("using default keyId {}.", keyId);
            } else {
                String errorMsg = "keyId is not set up yet, unable to encrypt the configuration.";
                localInitException = new RuntimeException(errorMsg);
                LOGGER.error(AliyunConst.formatHelpMessage(errorMsg), localInitException);
                return;
            }
        } else {
            LOGGER.info("using keyId {}.", keyId);
        }
        
        this.isUseLocalCache = KmsUtils.parsePropertyValue(properties, AliyunConst.NACOS_CONFIG_ENCRYPTION_KMS_LOCAL_CACHE_SWITCH,
                AliyunConst.DEFAULT_KMS_LOCAL_CACHE_SWITCH);
        if (this.isUseLocalCache()) {
            this.kmsLocalCache = new KmsLocalCache(properties);
        }
        
        try {
            if (kmsVersion == AliyunConst.KmsVersion.Kmsv1) {
                kmsClient = createKmsV1Client(properties);
            } else if (kmsVersion == AliyunConst.KmsVersion.Kmsv3) {
                kmsClient = createKmsV3Client(properties);
            }
        } catch (ClientException e) {
            LOGGER.error(AliyunConst.formatHelpMessage("kms init failed."), e);
            localInitException = e;
        } catch (Exception e) {
            LOGGER.error(AliyunConst.formatHelpMessage("create kms client failed."), e);
            localInitException = e;
        }
        try {
            asyncProcessor = new AsyncProcessor();
        } catch (Exception e) {
            LOGGER.error("init async processor failed.", e);
        }
    }

    /**
    * init kms v1 client, accessing the KMS service through a shared gateway.
    *
    * @date 2023/9/19
    * @description
    * @param properties
    * @return com.aliyuncs.IAcsClient
    * @throws
    */
    private IAcsClient createKmsV1Client(Properties properties) {
        String regionId = properties.getProperty(REGION_ID, System.getProperty(REGION_ID, System.getenv(REGION_ID)));
        String kmsRegionId = properties.getProperty(KMS_REGION_ID, System.getProperty(KMS_REGION_ID, System.getenv(KMS_REGION_ID)));
        if (StringUtils.isBlank(regionId)) {
            regionId = kmsRegionId;
        }
        LOGGER.info("using regionId {}.", regionId);
        if (StringUtils.isBlank(kmsRegionId)) {
            kmsRegionId = regionId;
        }
        LOGGER.info("using kms regionId {}.", kmsRegionId);

        if (StringUtils.isBlank(kmsRegionId) && StringUtils.isBlank(regionId)) {
            String errorMsg = "region is not set up yet";
            LOGGER.error(AliyunConst.formatHelpMessage(errorMsg));
            localInitException = new RuntimeException(errorMsg);
            return null;
        }

        String ramRoleName= properties.getProperty(PropertyKeyConst.RAM_ROLE_NAME,
                System.getProperty(PropertyKeyConst.RAM_ROLE_NAME, System.getenv(PropertyKeyConst.RAM_ROLE_NAME)));
        LOGGER.info("using ramRoleName {}.", ramRoleName);

        String accessKey = properties.getProperty(PropertyKeyConst.ACCESS_KEY,
                System.getProperty(PropertyKeyConst.ACCESS_KEY, System.getenv(PropertyKeyConst.ACCESS_KEY)));
        LOGGER.info("using accessKey {}.", accessKey);

        String secretKey = properties.getProperty(PropertyKeyConst.SECRET_KEY,
                System.getProperty(PropertyKeyConst.SECRET_KEY, System.getenv(PropertyKeyConst.SECRET_KEY)));

        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT,
                System.getProperty(AliyunConst.KMS_ENDPOINT, System.getenv(AliyunConst.KMS_ENDPOINT)));
        if (!StringUtils.isBlank(kmsEndpoint)) {
            DefaultProfile.addEndpoint(regionId, "kms", kmsEndpoint);
        }
        LOGGER.info("using kmsEndpoint {}.", kmsEndpoint);

        IClientProfile profile = null;
        IAcsClient kmsClient = null;
        if (!StringUtils.isBlank(ramRoleName)) {
            profile = DefaultProfile.getProfile(regionId);
            AlibabaCloudCredentialsProvider alibabaCloudCredentialsProvider = new InstanceProfileCredentialsProvider(
                    ramRoleName);
            kmsClient = new KmsTransferAcsClient(profile, alibabaCloudCredentialsProvider);
            LOGGER.info("successfully create kms client by using RAM role.");
        } else {
            profile = DefaultProfile.getProfile(regionId, accessKey, secretKey);
            kmsClient = new KmsTransferAcsClient(profile);
            LOGGER.info("successfully create kms client by using ak/sk.");
        }
        return kmsClient;
    }

    /**
    * init kms v3 client, accessing the KMS service through the KMS instance gateway.
    *
    * @date 2023/9/19
    * @description
    * @param properties
    * @return 
    * @throws 
    */
    private IAcsClient createKmsV3Client(Properties properties) throws ClientException {
        Config config = new Config();
        config.setProtocol("https");
        IClientProfile profile = null;

        String kmsClientKeyContent = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY,
                    System.getProperty(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, System.getenv(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY)));
        if (!StringUtils.isBlank(kmsClientKeyContent)) {
            LOGGER.info("using {}: {}.", AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, kmsClientKeyContent);
            config.setClientKeyContent(kmsClientKeyContent);
        } else {
            String errorMsg = null;
            LOGGER.info("{} is empty, will read from file.", AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY);
            String kmsClientKeyFilePath = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY,
                    System.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY, System.getenv(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY)));
            if (!StringUtils.isBlank(kmsClientKeyFilePath)) {
                String s = readFileToString(kmsClientKeyFilePath);
                if (!StringUtils.isBlank(s)) {
                    LOGGER.info("using kmsClientKeyFilePath: {}.", kmsClientKeyFilePath);
                    config.setClientKeyFile(kmsClientKeyFilePath);
                } else {
                    errorMsg = "both config from kmsClientKeyContent and kmsClientKeyFilePath is empty";
                }
            } else {
                errorMsg = "kmsClientKeyFilePath is empty";
            }
            if (!StringUtils.isBlank(errorMsg)) {
                localInitException = new RuntimeException(errorMsg);
                return null;
            }
        }

        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT,
                System.getProperty(AliyunConst.KMS_ENDPOINT, System.getenv(AliyunConst.KMS_ENDPOINT)));
        if (StringUtils.isBlank(kmsEndpoint)) {
            String errorMsg = String.format("%s is empty", AliyunConst.KMS_ENDPOINT);
            localInitException = new RuntimeException(errorMsg);
            return null;
        } else {
            LOGGER.info("using kmsEndpoint: {}.", kmsEndpoint);
            config.setEndpoint(kmsEndpoint);
        }

        String kmsPassword = properties.getProperty(AliyunConst.KMS_PASSWORD_KEY,
                System.getProperty(AliyunConst.KMS_PASSWORD_KEY, System.getenv(AliyunConst.KMS_PASSWORD_KEY)));
        if (StringUtils.isBlank(kmsPassword)) {
            String errorMsg = String.format("%s is empty", AliyunConst.KMS_PASSWORD_KEY);
            localInitException = new RuntimeException(errorMsg);
            return null;
        } else {
            LOGGER.info("using kmsPassword prefix: {}.", kmsPassword.substring(kmsPassword.length() / 8));
            config.setPassword(kmsPassword);
        }

        String kmsCaFileContent = properties.getProperty(AliyunConst.KMS_CA_FILE_CONTENT,
                System.getProperty(AliyunConst.KMS_CA_FILE_CONTENT, System.getenv(AliyunConst.KMS_CA_FILE_CONTENT)));
        if (!StringUtils.isBlank(kmsCaFileContent)) {
            LOGGER.info("using {}: {}.", AliyunConst.KMS_CA_FILE_CONTENT, kmsCaFileContent);
            config.setCa(kmsCaFileContent);
        } else {
            String errorMsg = null;
            LOGGER.info("{} is empty, will read from file.", AliyunConst.KMS_CA_FILE_CONTENT);
            String kmsCaFilePath = properties.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY,
                    System.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY, System.getenv(AliyunConst.KMS_CA_FILE_PATH_KEY)));
            if (!StringUtils.isBlank(kmsCaFilePath)) {
                config.setCaFilePath(kmsCaFilePath);
            } else {
                errorMsg = "kmsCaFilePath is empty";
                config.setCaFilePath(null);
            }
            if (!StringUtils.isBlank(errorMsg)) {
                LOGGER.warn(AliyunConst.formatHelpMessage(errorMsg));
                profile = DefaultProfile.getProfile(config.getRegionId(), "ak", "sk", "sts");
                HttpClientConfig httpClientConfig = HttpClientConfig.getDefault();
                httpClientConfig.setIgnoreSSLCerts(true);
                profile.setHttpClientConfig(httpClientConfig);
            }
        }

        if (profile == null) {
            return new KmsTransferAcsClient(config);
        }
        return new KmsTransferAcsClient(profile, config);
    }

    @Override
    public void doFilter(IConfigRequest request, IConfigResponse response, IConfigFilterChain filterChain)
            throws NacosException {
        String dataId = null;
        String group = null;
        try {
            if (request != null) {
                dataId = (String) request.getParameter(DATA_ID);
                group = (String) request.getParameter(GROUP);
                if (dataId.startsWith(CIPHER_PREFIX)) {
                    if (!StringUtils.isBlank((String)request.getParameter(CONTENT))) {
                        request.putParameter(CONTENT, encrypt(keyId, request));
                    }
                }

                filterChain.doFilter(request, response);
            }
            if (response != null) {
                dataId = (String) response.getParameter(DATA_ID);
                group = (String) response.getParameter(GROUP);
                if (dataId.startsWith(CIPHER_PREFIX)) {
                    if (!StringUtils.isBlank((String)response.getParameter(CONTENT))) {
                        response.putParameter(CONTENT, decrypt(response));
                    }
                }
            }
        } catch (ClientException e) {
            String message = String.format("KMS message:[%s], error message:[%s], dataId: %s, groupId: %s", e.getMessage(), e.getErrMsg(), dataId, group);
            throw new NacosException(NacosException.HTTP_CLIENT_ERROR_CODE, AliyunConst.formatHelpMessage(message), e);
        } catch (Exception e) {
            throw new NacosException(NacosException.INVALID_PARAM, AliyunConst.formatHelpMessage(e.getMessage()), e);
        }
    }

    private String decrypt(IConfigResponse response) throws Exception {
        String dataId = (String) response.getParameter(DATA_ID);
        String group = (String) response.getParameter(GROUP);
        String encryptedContent = (String) response.getParameter(CONTENT);
        String encryptedDataKey = (String) response.getParameter(ENCRYPTED_DATA_KEY);
        String result = null;
        String dataKey = null;
        boolean isUsedCache = false;
        
        //prefer to use kms service
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            if (!StringUtils.isBlank(encryptedDataKey)) {
                try {
                    dataKey = decrypt(encryptedDataKey);
                } catch (Exception e) {
                    //use local cache protection
                    LOGGER.error("decrypt config:[{}] failed by using kms service: {}. will use local cache.",
                            this.getGroupKey2(dataId, group), e.getMessage(), e);
                    KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId, encryptedDataKey, encryptedContent);
                    if (localCacheItem != null) {
                        dataKey = localCacheItem.getPlainDataKey();
                        isUsedCache = true;
                    } else {
                        throw e;
                    }
                }
                if (StringUtils.isBlank(dataKey)) {
                    //use local cache protection
                    LOGGER.warn("decrypt config [{}] with empty dataKey by using kms service. will use local cache.", this.getGroupKey2(dataId, group));
                    KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId, encryptedDataKey, encryptedContent);
                    if (localCacheItem != null) {
                        dataKey = localCacheItem.getPlainDataKey();
                        isUsedCache = true;
                    } else {
                        throw new RuntimeException("failed to decrypt encryptedDataKey with empty value");
                    }
                }
                result = AesUtils.decrypt((String) response.getParameter(CONTENT), dataKey, "UTF-8");
                if (StringUtils.isBlank(result)) {
                    throw new RuntimeException("failed to decrypt content with empty value");
                }
                //update local cache
                if (!isUsedCache) {
                    getKmsLocalCache().put(this.getGroupKey2(dataId, group), new KmsLocalCache.LocalCacheItem(encryptedDataKey, encryptedContent, dataKey, null));
                }
            } else {
                throw new RuntimeException("encrypted failed encryptedDataKey is empty");
            }
        } else {
            try {
                result = decrypt(encryptedContent);
            } catch (Exception e) {
                //use local cache protection
                LOGGER.error("decrypt config:[{}] failed by using kms service: {}. will use local cache.",
                        this.getGroupKey2(dataId, group), e.getMessage(), e);
                KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId, encryptedDataKey, encryptedContent);
                if (localCacheItem != null) {
                    result = localCacheItem.getPlainContent();
                    isUsedCache = true;
                } else {
                    throw e;
                }
            }
            if (StringUtils.isBlank(result)) {
                //use local cache protection
                LOGGER.warn("decrypt config [{}] with empty content by using kms service. will use local cache.", this.getGroupKey2(dataId, group));
                KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId, encryptedDataKey, encryptedContent);
                if (localCacheItem != null) {
                    result = localCacheItem.getPlainContent();
                    isUsedCache = true;
                } else {
                    throw new RuntimeException("failed to decrypt content with empty value");
                }
            }
            //update local cache
            if (!isUsedCache) {
                getKmsLocalCache().put(this.getGroupKey2(dataId, group), new KmsLocalCache.LocalCacheItem(null, encryptedContent, null, result));
            }
        }
        if (StringUtils.isBlank(result)) {
            throw new RuntimeException("decrypt failed with empty result.");
        }
        return result;
    }

    private String decrypt(String content) throws Exception {
        if (kmsClient == null) {
            if (localInitException != null) {
                throw localInitException;
            } else {
                throw new RuntimeException("kms client isn't initialized. " +
                        "For more information, please check: " + AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
            }
        }
        AtomicReference<String> resultContent = new AtomicReference<>();
        final DecryptRequest decReq = new DecryptRequest();
        decReq.setSysProtocol(ProtocolType.HTTPS);
        decReq.setSysMethod(MethodType.POST);
        decReq.setAcceptFormat(FormatType.JSON);
        decReq.setCiphertextBlob(content);
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set(kmsClient.getAcsResponse(decReq).getPlaintext());
            } catch (ClientException e) {
                //some exception need to return false to retry
                if (KmsUtils.judgeNeedRecoveryException(e)) {
                    return false;
                }
                throw new RuntimeException(e);
            }
            return true;
        }, defaultRetryTimes, defaultTimeoutMilliseconds);
        return resultContent.get();
    }

    private String encrypt(String keyId, IConfigRequest configRequest) throws Exception {
        if (kmsClient == null) {
            if (localInitException != null) {
                throw localInitException;
            } else {
                throw new RuntimeException("kms client isn't initialized. " +
                        "For more information, please check: " + AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
            }
        }
        if (StringUtils.isBlank(keyId)) {
            throw new RuntimeException("keyId is not set up yet, unable to encrypt the configuration. " +
                    "For more information, please check: " + AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
        }
        
        protectKeyId(keyId);
        
        String dataId = (String) configRequest.getParameter(DATA_ID);
        String group = (String) configRequest.getParameter(GROUP);
        String plainContent = (String) configRequest.getParameter(CONTENT);
        String result; //encryptedContent
        String dataKey;
        String encryptedDataKey;
        boolean isUsedCache = false;
        
        //prefer to use kms service
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            String keySpec = null;
            if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX)) {
                keySpec = KMS_KEY_SPEC_AES_128;
            } else {
                keySpec = KMS_KEY_SPEC_AES_256;
            }
            try {
                GenerateDataKeyResponse generateDataKeyResponse = generateDataKey(keyId, keySpec);
                dataKey = generateDataKeyResponse.getPlaintext();
                encryptedDataKey = generateDataKeyResponse.getCiphertextBlob();
            } catch (Exception e) {
                //use local cache protection
                LOGGER.error("encrypt config(generate DataKey):[{}] failed by using kms service: {}. will use local cache.",
                        this.getGroupKey2(dataId, group), e.getMessage(), e);
                KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId);
                if (localCacheItem != null) {
                    encryptedDataKey = localCacheItem.getEncryptedDataKey();
                    dataKey = localCacheItem.getPlainDataKey();
                    isUsedCache = true;
                } else {
                    throw e;
                }
            }
            if (StringUtils.isBlank(dataKey) || StringUtils.isBlank(encryptedDataKey)) {
                //use local cache protection
                LOGGER.warn("encrypt config [{}] with empty dataKey by using kms service. will use local cache.", this.getGroupKey2(dataId, group));
                KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId);
                if (localCacheItem != null) {
                    encryptedDataKey = localCacheItem.getEncryptedDataKey();
                    dataKey = localCacheItem.getPlainDataKey();
                    isUsedCache = true;
                } else {
                    throw new RuntimeException("get generateDataKey failed with empty content. " +
                            "For more information, please check: " + AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
                }
            }
            configRequest.putParameter(ENCRYPTED_DATA_KEY, encryptedDataKey);
            result = AesUtils.encrypt((String) configRequest.getParameter(CONTENT), dataKey, "UTF-8");
            
            //update local cache
            if (!isUsedCache) {
                getKmsLocalCache().put(this.getGroupKey2(dataId, group), new KmsLocalCache.LocalCacheItem(
                        encryptedDataKey, result, dataKey, null));
            }
        } else {
            try {
                result = encrypt(keyId, plainContent);
            } catch (Exception e) {
                //use local cache protection
                LOGGER.error("encrypt config:[{}] failed by using kms service: {}. will use local cache.",
                        this.getGroupKey2(dataId, group), e.getMessage(), e);
                KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId);
                if (localCacheItem != null) {
                    return localCacheItem.getEncryptedContent();
                } else {
                    throw e;
                }
            }
            if (StringUtils.isBlank(result)) {
                //use local cache protection
                LOGGER.warn("encrypt config [{}] with empty content by using kms service. will use local cache.", this.getGroupKey2(dataId, group));
                KmsLocalCache.LocalCacheItem localCacheItem = getLocalCacheItem(group, dataId);
                if (localCacheItem != null) {
                    return localCacheItem.getEncryptedContent();
                } else {
                    throw new RuntimeException("encrypt failed with empty result.");
                }
            }
            //update local cache
            getKmsLocalCache().put(this.getGroupKey2(dataId, group), new KmsLocalCache.LocalCacheItem(
                    null, result, null, plainContent));
        }
        if (StringUtils.isBlank(result)) {
            throw new RuntimeException("encrypt failed with empty result.");
        }
        return result;
    }
    
    public String encrypt(String keyId, String plainText) throws Exception {
        AtomicReference<String> resultContent = new AtomicReference<>();
        final EncryptRequest encReq = new EncryptRequest();
        encReq.setProtocol(ProtocolType.HTTPS);
        encReq.setAcceptFormat(FormatType.JSON);
        encReq.setMethod(MethodType.POST);
        encReq.setKeyId(keyId);
        encReq.setPlaintext(plainText);
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set( kmsClient.getAcsResponse(encReq).getCiphertextBlob());
            } catch (ClientException e) {
                //some exception need to return false to retry
                if (KmsUtils.judgeNeedRecoveryException(e)) {
                    return false;
                }
                throw new RuntimeException(e);
            }
            return true;
        
        }, defaultRetryIntervalMilliseconds, defaultTimeoutMilliseconds);
        return resultContent.get();
    }

    public GenerateDataKeyResponse generateDataKey(String keyId, String keySpec) throws Exception {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();
        generateDataKeyRequest.setAcceptFormat(FormatType.JSON);
        generateDataKeyRequest.setKeyId(keyId);
        generateDataKeyRequest.setKeySpec(keySpec);
        AtomicReference<GenerateDataKeyResponse> resultContent = new AtomicReference<>();
        locallyRunWithRetryTimesAndTimeout(() -> {
            try {
                resultContent.set(kmsClient.getAcsResponse(generateDataKeyRequest));
            } catch (ClientException e) {
                //some exception need to return false to retry
                if (KmsUtils.judgeNeedRecoveryException(e)) {
                    return false;
                }
                throw new RuntimeException(e);
            }
            return true;
        }, defaultRetryTimes, defaultTimeoutMilliseconds);
        return resultContent.get();
    }

    private void protectKeyId(String keyId) {
        if (!addedKeys.contains(keyId)) {
            synchronized (addedKeys) {
                addedKeys.add(keyId);
                asyncProcessor.addTack(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            if (kmsClient == null) {
                                LOGGER.error("kms client hasn't initiated.");
                                return;
                            }
                            DescribeKeyRequest describeKeyRequest = new DescribeKeyRequest();
                            describeKeyRequest.setKeyId(keyId);
                            try {
                                DescribeKeyResponse describeKeyResponse = kmsClient.getAcsResponse(describeKeyRequest);
                                if (describeKeyResponse.getKeyMetadata()!= null) {
                                    String arn = describeKeyResponse.getKeyMetadata().getArn();
                                    LOGGER.info("set deletion protection for keyId[{}], arn[{}]", keyId, arn);

                                    SetDeletionProtectionRequest setDeletionProtectionRequest = new SetDeletionProtectionRequest();
                                    setDeletionProtectionRequest.setProtectedResourceArn(arn);
                                    setDeletionProtectionRequest.setEnableDeletionProtection(true);
                                    setDeletionProtectionRequest.setDeletionProtectionDescription("key is used by nacos-client");
                                    try {
                                        kmsClient.getAcsResponse(setDeletionProtectionRequest);
                                    } catch (ClientException e) {
                                        LOGGER.error("set deletion protect failed, keyId: {}.", keyId);
                                        throw e;
                                    }
                                } else {
                                    addedKeys.remove(keyId);
                                    LOGGER.warn("keyId meta is null, cannot set key protection");
                                }
                            } catch (ClientException e) {
                                LOGGER.error("describe key failed, keyId: {}.", keyId);
                                throw e;
                            }
                        } catch (Exception e) {
                            addedKeys.remove(keyId);
                            LOGGER.error("execute async task failed", e);
                        }

                    }
                });
            }
        }
    }
    
    private static void locallyRunWithRetryTimesAndTimeout(Supplier<Boolean> runnable, int retryTimes, long timeout)
            throws Exception {
        int locallyRetryTimes = 0;
        long beginTime = System.currentTimeMillis();
        while (locallyRetryTimes++ < retryTimes && System.currentTimeMillis() < beginTime + timeout) {
            if (runnable.get()) {
                break;
            }
            Thread.sleep(defaultRetryIntervalMilliseconds);
        }
    }

    private static String readFileToString(String filePath) {
        File file = getFileByPath(filePath);
        if (file == null || !file.exists()) {
            return null;
        }
        try {
            Path path = Paths.get(file.getAbsolutePath());
            byte[] fileContent = Files.readAllBytes(path);
            return new String(fileContent, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static File getFileByPath(String filePath) {
        File file = new File(filePath);
        if (!file.exists()) {
            String path = AliyunConfigFilter.class.getClassLoader().getResource("").getPath();
            if (!(file = new File(path + filePath)).exists()) {
                path = Paths.get(filePath).toAbsolutePath().toString();
                if (!(file = new File(path)).exists()) {
                    return null;
                }
            }
        }
        return file;
    }
    
    private boolean isUseLocalCache() {
        return this.isUseLocalCache;
    }
    
    private KmsLocalCache getKmsLocalCache() {
        return this.kmsLocalCache;
    }
    
    private KmsLocalCache.LocalCacheItem getLocalCacheItem(String group, String dataId, String encryptDataKey, String encryptedContent) {
        //check if open local cache
        if (!this.isUseLocalCache() || this.getKmsLocalCache() == null) {
            return null;
        }
        
        //check if cache is ready
        KmsLocalCache.LocalCacheItem localCacheItem = this.getKmsLocalCache().get(this.getGroupKey2(dataId, group));
        if (localCacheItem == null) {
            return null;
        }
        
        //check if cache is valid
        if (checkIfKmsCacheItemValidByDecrypt(localCacheItem, dataId, encryptDataKey, encryptedContent)) {
            return null;
        }
        return localCacheItem;
    }
    
    private KmsLocalCache.LocalCacheItem getLocalCacheItem(String group, String dataId) {
        //check if open local cache
        if (!this.isUseLocalCache() || this.getKmsLocalCache() == null) {
            return null;
        }
        
        //check if cache is ready
        KmsLocalCache.LocalCacheItem localCacheItem = this.getKmsLocalCache().get(this.getGroupKey2(dataId, group));
        if (localCacheItem == null) {
            return null;
        }
        
        //check if cache is valid
        if (checkIfKmsCacheItemValidByEncrypt(localCacheItem, dataId)) {
            return null;
        }
        
        return localCacheItem;
    }
    
    private boolean checkIfKmsCacheItemValidByEncrypt(KmsLocalCache.LocalCacheItem localCacheItem, String dataId) {
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedDataKey())
                    && !StringUtils.isBlank(localCacheItem.getEncryptedContent())
                    && !StringUtils.isBlank(localCacheItem.getPlainDataKey());
        } else if (dataId.startsWith(CIPHER_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedContent())
                    && !StringUtils.isBlank(localCacheItem.getPlainContent());
        }
        return false;
    }
    
    private boolean checkIfKmsCacheItemValidByDecrypt(KmsLocalCache.LocalCacheItem localCacheItem, String dataId, String encryptedDataKey, String encryptedContent) {
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedDataKey())
                    && !StringUtils.isBlank(localCacheItem.getEncryptedContent())
                    && !StringUtils.isBlank(localCacheItem.getPlainDataKey())
                    && localCacheItem.getEncryptedDataKey().equals(encryptedDataKey)
                    && localCacheItem.getEncryptedContent().equals(encryptedContent);
        } else if (dataId.startsWith(CIPHER_PREFIX)) {
            return !StringUtils.isBlank(localCacheItem.getEncryptedContent())
                    && !StringUtils.isBlank(localCacheItem.getPlainContent())
                    && localCacheItem.getEncryptedContent().equals(encryptedContent);
        }
        return false;
    }
    
    private String getGroupKey2(String dataId, String group) {
        StringBuilder sb = new StringBuilder();
        urlEncode(dataId, sb);
        sb.append('+');
        urlEncode(group, sb);
        return sb.toString();
    }
    
    private void urlEncode(String str, StringBuilder sb) {
        for (int idx = 0; idx < str.length(); ++idx) {
            char c = str.charAt(idx);
            if ('+' == c) {
                sb.append("%2B");
            } else if ('%' == c) {
                sb.append("%25");
            } else {
                sb.append(c);
            }
        }
    }
    
    @Override
    public int getOrder() {
        return 1;
    }

    @Override
    public String getFilterName() {
        return this.getClass().getName();
    }
}
