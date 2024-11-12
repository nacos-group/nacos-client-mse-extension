package com.alibaba.nacos.client.aliyun.auth.injector;

import com.alibaba.nacos.api.common.Constants;
import com.alibaba.nacos.api.naming.utils.NamingUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.alibaba.nacos.client.auth.ram.utils.SignUtil;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.plugin.auth.api.RequestResource;

import java.util.HashMap;
import java.util.Map;

import static com.alibaba.nacos.client.utils.LogUtils.NAMING_LOGGER;

/**
 * Ram resource injector with aliyun extension for nacos naming module.
 *
 * @author xiweng.yy
 */
public class NamingExtensionResourceInjector extends AbstractExtensionResourceInjector {
    
    private static final String SIGNATURE_FILED = "signature";
    
    private static final String DATA_FILED = "data";
    
    private static final String AK_FILED = "ak";
    
    @Override
    protected String getAccessKeyHeaderKey() {
        return AK_FILED;
    }
    
    @Override
    protected Map<String, String> calculateSignature(RequestResource resource, String actualSecretKey,
            ExtensionRamContext ramContext) {
        Map<String, String> result = new HashMap<>();
        try {
            String signData = getSignData(getGroupedServiceName(resource));
            String signature = SignUtil.sign(signData, actualSecretKey);
            result.put(SIGNATURE_FILED, signature);
            result.put(DATA_FILED, signData);
        } catch (Exception e) {
            NAMING_LOGGER.warn("Calculate auth signature for naming failed.", e);
        }
        return result;
    }
    
    private String getGroupedServiceName(RequestResource resource) {
        if (resource.getResource().contains(Constants.SERVICE_INFO_SPLITER) || StringUtils
                .isBlank(resource.getGroup())) {
            return resource.getResource();
        }
        return NamingUtils.getGroupedNameOptional(resource.getResource(), resource.getGroup());
    }
    
    private String getSignData(String serviceName) {
        return StringUtils.isNotEmpty(serviceName) ? System.currentTimeMillis() + Constants.SERVICE_INFO_SPLITER
                + serviceName : String.valueOf(System.currentTimeMillis());
    }
}
