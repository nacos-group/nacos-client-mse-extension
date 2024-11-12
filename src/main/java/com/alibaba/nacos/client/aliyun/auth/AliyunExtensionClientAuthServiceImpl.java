package com.alibaba.nacos.client.aliyun.auth;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.client.aliyun.auth.injector.ConfigExtensionResourceInjector;
import com.alibaba.nacos.client.aliyun.auth.injector.NamingExtensionResourceInjector;
import com.alibaba.nacos.client.aliyun.auth.provider.AutoRotateCredentialsProvider;
import com.alibaba.nacos.client.aliyun.auth.provider.CredentialsUriCredentialsProvider;
import com.alibaba.nacos.client.aliyun.auth.provider.ExtensionCredentialsProvider;
import com.alibaba.nacos.client.aliyun.auth.provider.OidcRoleArnCredentialsProvider;
import com.alibaba.nacos.client.aliyun.auth.provider.RamRoleArnCredentialsProvider;
import com.alibaba.nacos.client.aliyun.auth.provider.StsTokenCredentialsProvider;
import com.alibaba.nacos.client.auth.ram.injector.AbstractResourceInjector;
import com.alibaba.nacos.plugin.auth.api.LoginIdentityContext;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import com.alibaba.nacos.plugin.auth.constant.SignType;
import com.alibaba.nacos.plugin.auth.spi.client.AbstractClientAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Nacos ClientAuthServiceImpl for aliyun extension auth way.
 *
 * @author xiweng.yy
 */
public class AliyunExtensionClientAuthServiceImpl extends AbstractClientAuthService {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(AliyunExtensionClientAuthServiceImpl.class);
    
    private final Set<ExtensionCredentialsProvider> credentialsProviders;
    
    private final Map<String, AbstractResourceInjector> resourceInjectors;
    
    private ExtensionCredentialsProvider matchedProvider;
    
    public AliyunExtensionClientAuthServiceImpl() {
        this.credentialsProviders = new HashSet<>();
        this.credentialsProviders.add(new CredentialsUriCredentialsProvider());
        this.credentialsProviders.add(new StsTokenCredentialsProvider());
        this.credentialsProviders.add(new OidcRoleArnCredentialsProvider());
        this.credentialsProviders.add(new RamRoleArnCredentialsProvider());
        this.credentialsProviders.add(new AutoRotateCredentialsProvider());
        this.resourceInjectors = new HashMap<>();
        this.resourceInjectors.put(SignType.NAMING, new NamingExtensionResourceInjector());
        this.resourceInjectors.put(SignType.CONFIG, new ConfigExtensionResourceInjector());
    }
    
    @Override
    public Boolean login(Properties properties) {
        for (ExtensionCredentialsProvider each : credentialsProviders) {
            if (each.matchProvider(properties)) {
                LOGGER.info("Match credentials provider: {}", each.getClass().getName());
                matchedProvider = each;
                break;
            }
        }
        try {
            if (null == matchedProvider) {
                return false;
            }
            matchedProvider.init(properties);
            return true;
        } catch (Exception e) {
            LOGGER.warn("Init for Credential Provider {} failed.", matchedProvider.getClass().getName(), e);
            return false;
        }
    }
    
    @Override
    public LoginIdentityContext getLoginIdentityContext(RequestResource resource) {
        LoginIdentityContext result = new LoginIdentityContext();
        if (null == matchedProvider) {
            return result;
        }
        ExtensionRamContext ramContext = matchedProvider.getCredentialsForNacosClient();
        if (!ramContext.validate() || notFountInjector(resource.getType())) {
            return result;
        }
        resourceInjectors.get(resource.getType()).doInject(resource, ramContext, result);
        return result;
    }
    
    private boolean notFountInjector(String type) {
        if (!resourceInjectors.containsKey(type)) {
            LOGGER.warn("Injector for type {} not found, will use default ram identity context.", type);
            return true;
        }
        return false;
    }
    
    @Override
    public void shutdown() throws NacosException {
        if (null != matchedProvider) {
            matchedProvider.shutdown();
        }
    }
}
