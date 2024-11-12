package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.alibaba.nacos.common.utils.StringUtils;

import java.util.Properties;

/**
 * Aliyun CredentialsProvider for Sts token type which for some untrusted environment template used.
 *
 * @author xiweng.yy
 */
public class StsTokenCredentialsProvider implements ExtensionCredentialsProvider {
    
    private String accessKey;
    
    private String secretKey;
    
    private String securityToken;
    
    private String signatureRegionId;
    
    @Override
    public boolean matchProvider(Properties properties) {
        String accessKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_ID);
        String secretKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_SECRET);
        String securityToken = getNacosProperties(properties, ExtensionAuthPropertyKey.SECURITY_TOKEN);
        return StringUtils.isNotBlank(accessKey) && StringUtils.isNotBlank(secretKey) && StringUtils.isNotBlank(
                securityToken);
    }
    
    @Override
    public void init(Properties properties) {
        accessKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_ID);
        secretKey = getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_SECRET);
        securityToken = getNacosProperties(properties, ExtensionAuthPropertyKey.SECURITY_TOKEN);
        signatureRegionId = getSignatureRegionId(properties);
    }
    
    @Override
    public ExtensionRamContext getCredentialsForNacosClient() {
        ExtensionRamContext extensionRamContext = new ExtensionRamContext();
        extensionRamContext.setAccessKey(accessKey);
        extensionRamContext.setSecretKey(secretKey);
        extensionRamContext.setSecurityToken(securityToken);
        extensionRamContext.setExtensionSignatureRegionId(signatureRegionId);
        return extensionRamContext;
    }
    
    @Override
    public void shutdown() throws NacosException {
    }
}
