package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.aliyun.credentials.Client;
import com.aliyun.credentials.models.Config;
import com.aliyun.credentials.models.CredentialModel;

import java.lang.reflect.Field;
import java.util.Properties;

/**
 * Abstract credentials provider by aliyun credentials client.
 *
 * @author xiweng.yy
 */
public abstract class AbstractCredentialClientProvider implements ExtensionCredentialsProvider {
    
    private Client credentialsClient;
    
    private String signatureRegionId;
    
    @Override
    public void init(Properties properties) {
        synchronized (this) {
            if (null == credentialsClient) {
                Config credentialsConfig = generateCredentialsConfig(properties);
                credentialsClient = new Client(credentialsConfig);
            }
        }
        signatureRegionId = getSignatureRegionId(properties);
    }
    
    /**
     * Generate credentials config by properties.
     *
     * @param properties nacos client properties which same as parameters {@link #matchProvider(Properties)}
     * @return credentials config
     */
    protected abstract Config generateCredentialsConfig(Properties properties);
    
    @Override
    public ExtensionRamContext getCredentialsForNacosClient() {
        ExtensionRamContext ramContext = new ExtensionRamContext();
        if (null != credentialsClient) {
            CredentialModel credentialModel = credentialsClient.getCredential();
            ramContext.setAccessKey(credentialModel.getAccessKeyId());
            ramContext.setSecretKey(credentialModel.getAccessKeySecret());
            ramContext.setSecurityToken(credentialModel.getSecurityToken());
        }
        ramContext.setExtensionSignatureRegionId(signatureRegionId);
        return ramContext;
    }
    
    @Override
    public void shutdown() throws NacosException {
        if (null != credentialsClient) {
            doCloseCredentialsClient();
        }
    }
    
    /**
     * Aliyun Credentials Client don't include close or shutdown method, but it might be with session or Thread Pool.
     *
     * <p>
     *     For invalid leak of connection and thread pool, template use reflect to close inner resource.
     *     If new version provide close method, will use it.
     * </p>
     */
    private void doCloseCredentialsClient() {
        try {
            Field field = credentialsClient.getClass().getDeclaredField("credentialsProvider");
            field.setAccessible(true);
            Object innerProvider = field.get(credentialsClient);
            if (innerProvider instanceof AutoCloseable) {
                ((AutoCloseable) innerProvider).close();
            }
        } catch (Exception ignored) {
        }
    }
    
    protected Config injectCommonBasicConfig(Properties properties, Config config) {
        config.setAccessKeyId(getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_ID));
        config.setAccessKeySecret(getNacosProperties(properties, ExtensionAuthPropertyKey.ACCESS_KEY_SECRET));
        String securityToken = getNacosProperties(properties, ExtensionAuthPropertyKey.SECURITY_TOKEN);
        if (!StringUtils.isEmpty(securityToken)) {
            config.setSecurityToken(securityToken);
        }
        String policy = getNacosProperties(properties, ExtensionAuthPropertyKey.POLICY);
        if (!StringUtils.isEmpty(policy)) {
            config.setPolicy(policy);
        }
        String roleSessionExpiration = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_EXPIRATION);
        if (!StringUtils.isEmpty(roleSessionExpiration)) {
            config.setRoleSessionExpiration(Integer.parseInt(roleSessionExpiration));
        }
        return config;
    }
}
