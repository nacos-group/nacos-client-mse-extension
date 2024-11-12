package com.alibaba.nacos.client.aliyun.auth.injector;

import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.aliyun.auth.ExtensionAuthConstants;
import com.alibaba.nacos.client.aliyun.auth.ExtensionRamContext;
import com.alibaba.nacos.client.auth.ram.RamConstants;
import com.alibaba.nacos.client.auth.ram.RamContext;
import com.alibaba.nacos.client.auth.ram.injector.AbstractResourceInjector;
import com.alibaba.nacos.client.auth.ram.utils.CalculateV4SigningKeyUtil;
import com.alibaba.nacos.plugin.auth.api.LoginIdentityContext;
import com.alibaba.nacos.plugin.auth.api.RequestResource;

import java.util.Map;

/**
 * Abstract resource injector for extension.
 *
 * @author xiweng.yy
 */
public abstract class AbstractExtensionResourceInjector extends AbstractResourceInjector {
    
    private boolean supportV4signature;
    
    protected AbstractExtensionResourceInjector() {
        try {
            Class.forName(ExtensionAuthConstants.V4_SIGNATURE_UTIL_CLASS);
            supportV4signature = true;
        } catch (ClassNotFoundException e) {
            supportV4signature = false;
        }
    }
    
    @Override
    public void doInject(RequestResource resource, RamContext context, LoginIdentityContext result) {
        ExtensionRamContext ramContext = (ExtensionRamContext) context;
        result.setParameter(getAccessKeyHeaderKey(), ramContext.getAccessKey());
        if (ramContext.isEphemeralAccessKeyId()) {
            result.setParameter(ExtensionAuthConstants.SECURITY_TOKEN_HEADER, ramContext.getSecurityToken());
        }
        String secretKey = trySignatureWithV4(ramContext, result);
        Map<String, String> signatures = calculateSignature(resource, secretKey, ramContext);
        result.setParameters(signatures);
    }
    
    /**
     * Try to sign with v4 signature.
     *
     * @param context ram context with extension
     * @param result login identity context
     * @return actual secret key, if not support v4 signature or not config signature region, return secret key directly,otherwise return v4 signature.
     */
    protected String trySignatureWithV4(ExtensionRamContext context, LoginIdentityContext result) {
        if (!supportV4signature || StringUtils.isEmpty(context.getExtensionSignatureRegionId())) {
            return context.getSecretKey();
        }
        result.setParameter(RamConstants.SIGNATURE_VERSION, RamConstants.V4);
        return CalculateV4SigningKeyUtil.finalSigningKeyStringWithDefaultInfo(context.getSecretKey(),
                context.getExtensionSignatureRegionId());
    }
    
    /**
     * Get access key header key according to child module.
     *
     * @return access key header key.
     */
    protected abstract String getAccessKeyHeaderKey();
    
    /**
     * Calculate signature according to child module.
     *
     * @param resource request resource
     * @param actualSecretKey actual secret key, if support v4 and config signature region, it's v4 key, otherwise it's original key.
     * @param ramContext extension ram context
     * @return signature item maps.
     */
    protected abstract Map<String, String> calculateSignature(RequestResource resource, String actualSecretKey,
            ExtensionRamContext ramContext);
    
}
