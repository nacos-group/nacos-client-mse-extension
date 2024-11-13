package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.exception.runtime.NacosRuntimeException;
import com.alibaba.nacos.api.model.v2.ErrorCode;
import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.alibaba.nacos.common.utils.JacksonUtils;
import com.aliyuncs.kms.secretsmanager.client.SecretCacheClient;
import com.aliyuncs.kms.secretsmanager.client.SecretCacheClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.model.SecretInfo;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Properties;

/**
 * Aliyun credentials provider for auto rotate access key by KMS.
 *
 * @author xiweng.yy
 */
public class AutoRotateCredentialsProvider implements ExtensionCredentialsProvider {
    
    private SecretCacheClient client;
    
    private String secretName;
    
    private String signatureRegionId;
    
    @Override
    public boolean matchProvider(Properties properties) {
        return !StringUtils.isEmpty(getNacosProperties(properties, ExtensionAuthPropertyKey.SECRET_NAME));
    }
    
    @Override
    public void init(Properties properties) {
        secretName = getNacosProperties(properties, ExtensionAuthPropertyKey.SECRET_NAME);
        signatureRegionId = getSignatureRegionId(properties);
        buildSecretClient();
    }
    
    private synchronized void buildSecretClient() {
        try {
            if (null == client) {
                client = SecretCacheClientBuilder.newClient();
            }
        } catch (Exception e) {
            throw new NacosRuntimeException(ErrorCode.ILLEGAL_STATE.getCode(), e.getMessage(), e);
        }
    }
    
    @Override
    public ExtensionRamContext getCredentialsForNacosClient() {
        ExtensionRamContext result = new ExtensionRamContext();
        result.setEphemeralAccessKeyId(false);
        if (null == client) {
            return result;
        }
        try {
            SecretInfo secretInfo = client.getSecretInfo(secretName);
            JsonNode jsonNode = JacksonUtils.toObj(secretInfo.getSecretValue());
            result.setAccessKey(jsonNode.get("AccessKeyId").asText());
            result.setSecretKey(jsonNode.get("AccessKeySecret").asText());
            result.setExtensionSignatureRegionId(signatureRegionId);
        } catch (CacheSecretException e) {
            return result;
        }
        return result;
    }
    
    @Override
    public void shutdown() throws NacosException {
    }
}
