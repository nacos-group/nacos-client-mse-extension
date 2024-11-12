package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

/**
 * Aliyun CredentialsProvider for OIDC role arn type which most of Kubernetes situation.
 *
 * @author xiweng.yy
 */
public class OidcRoleArnCredentialsProvider extends AbstractCredentialClientProvider {
    
    @Override
    public boolean matchProvider(Properties properties) {
        String arnRole = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_ARN);
        String roleSessionName = getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_NAME);
        String oidcProviderArn = getNacosProperties(properties, ExtensionAuthPropertyKey.OIDC_PROVIDER_ARN);
        return !StringUtils.isEmpty(arnRole) && !StringUtils.isEmpty(roleSessionName) && !StringUtils.isEmpty(
                oidcProviderArn);
    }
    
    @Override
    protected Config generateCredentialsConfig(Properties properties) {
        Config config = new Config();
        config.setType("oidc_role_arn");
        config.setRoleArn(getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_ARN));
        config.setRoleSessionName(getNacosProperties(properties, ExtensionAuthPropertyKey.ROLE_SESSION_NAME));
        config.setOidcProviderArn(getNacosProperties(properties, ExtensionAuthPropertyKey.OIDC_PROVIDER_ARN));
        config.setOidcTokenFilePath(getNacosProperties(properties, ExtensionAuthPropertyKey.OIDC_TOKEN_FILE_PATH));
        return injectCommonBasicConfig(properties, config);
    }
}
