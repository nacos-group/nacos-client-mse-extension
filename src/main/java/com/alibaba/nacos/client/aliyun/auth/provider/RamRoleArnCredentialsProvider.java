package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

/**
 * Aliyun CredentialsProvider for ram role arn type which most of assume role situation.
 *
 * @author xiweng.yy
 */
public class RamRoleArnCredentialsProvider extends AbstractCredentialClientProvider {
    
    @Override
    public boolean matchProvider(Properties properties) {
        String arnRole = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_ARN);
        String roleSessionName = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_NAME);
        String oidcProviderArn = getNacosProperties(properties, ExtensionAuthPropertyKey.OIDC_PROVIDER_ARN);
        return !StringUtils.isEmpty(arnRole) && !StringUtils.isEmpty(roleSessionName) && StringUtils.isEmpty(
                oidcProviderArn);
    }
    
    @Override
    protected Config generateCredentialsConfig(Properties properties) {
        Config config = new Config();
        config.setType("ram_role_arn");
        config.setRoleArn(getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_ARN));
        config.setRoleSessionName(getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_NAME));
        return injectCommonBasicConfig(properties, config);
    }
}
