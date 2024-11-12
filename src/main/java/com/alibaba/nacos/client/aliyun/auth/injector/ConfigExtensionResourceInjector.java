package com.alibaba.nacos.client.aliyun.auth.injector;

import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.alibaba.nacos.client.auth.ram.utils.SpasAdapter;
import com.alibaba.nacos.client.utils.LogUtils;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import org.slf4j.Logger;

import java.util.HashMap;
import java.util.Map;

/**
 * Ram resource injector with aliyun extension for nacos config module.
 *
 * @author xiweng.yy
 */
public class ConfigExtensionResourceInjector extends AbstractExtensionResourceInjector {
    
    private static final Logger LOGGER = LogUtils.logger(ConfigExtensionResourceInjector.class);
    
    private static final String ACCESS_KEY_HEADER = "Spas-AccessKey";
    
    private static final String DEFAULT_RESOURCE = "";
    
    @Override
    protected String getAccessKeyHeaderKey() {
        return ACCESS_KEY_HEADER;
    }
    
    @Override
    protected Map<String, String> calculateSignature(RequestResource resource, String actualSecretKey,
            ExtensionRamContext ramContext) {
        Map<String, String> result = new HashMap<>();
        try {
            String resourceString = getResource(resource.getNamespace(), resource.getGroup());
            Map<String, String> signHeaders = SpasAdapter.getSignHeaders(resourceString, actualSecretKey);
            result.putAll(signHeaders);
        } catch (Exception e) {
            LOGGER.warn("Calculate auth signature for config failed.", e);
        }
        return result;
    }
    
    private String getResource(String tenant, String group) {
        if (StringUtils.isNotBlank(tenant) && StringUtils.isNotBlank(group)) {
            return tenant + "+" + group;
        }
        if (StringUtils.isNotBlank(group)) {
            return group;
        }
        if (StringUtils.isNotBlank(tenant)) {
            return tenant;
        }
        return DEFAULT_RESOURCE;
    }
}
