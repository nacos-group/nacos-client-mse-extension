package com.alibaba.nacos.client.aliyun.auth.provider;

import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthPropertyKey;
import com.aliyun.credentials.models.Config;

import java.util.Properties;

/**
 * Aliyun credentials provider for custom credential uri type.
 *
 * <p>
 *     This credentials provider is supported to get credential from custom credential uri.
 *     The custom uri should be in the following format: <a href="http://local_or_remote_uri/">http://local_or_remote_uri/</a>
 *     And the custom uri should response with code {@code 200} and with body json format:
 *     <code>
 *         {
 *              "Code": "Success",
 *              "AccessKeySecret": "AccessKeySecret",
 *              "AccessKeyId": "AccessKeyId",
 *              "Expiration": "2021-09-26T03:46:38Z",
 *              "SecurityToken": "SecurityToken"
 *          }
 *     </code>
 * </p>
 *
 * @author xiweng.yy
 */
public class CredentialsUriCredentialsProvider extends AbstractCredentialClientProvider {
    
    @Override
    public boolean matchProvider(Properties properties) {
        String credentialsURI = getNacosProperties(properties, ExtensionAuthPropertyKey.CREDENTIALS_URI);
        return !StringUtils.isEmpty(credentialsURI);
    }
    
    @Override
    protected Config generateCredentialsConfig(Properties properties) {
        Config config = new Config();
        config.setType("credentials_uri");
        config.setCredentialsUri(getNacosProperties(properties, ExtensionAuthPropertyKey.CREDENTIALS_URI));
        return config;
    }
}
