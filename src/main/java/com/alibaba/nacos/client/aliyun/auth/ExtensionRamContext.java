package com.alibaba.nacos.client.aliyun.auth;

import com.alibaba.nacos.client.auth.ram.RamContext;
import com.alibaba.nacos.common.utils.StringUtils;

/**
 * Extension ram context.
 *
 * @author xiweng.yy
 */
public class ExtensionRamContext extends RamContext {
    
    private String securityToken;
    
    /**
     * For adapter nacos-client 2.4.0 v4 signature.
     */
    private String extensionSignatureRegionId;
    
    private boolean ephemeralAccessKeyId = true;
    
    public String getSecurityToken() {
        return securityToken;
    }
    
    public void setSecurityToken(String securityToken) {
        this.securityToken = securityToken;
    }
    
    public String getExtensionSignatureRegionId() {
        return extensionSignatureRegionId;
    }
    
    public void setExtensionSignatureRegionId(String extensionSignatureRegionId) {
        this.extensionSignatureRegionId = extensionSignatureRegionId;
    }
    
    public boolean isEphemeralAccessKeyId() {
        return ephemeralAccessKeyId;
    }
    
    public void setEphemeralAccessKeyId(boolean ephemeralAccessKeyId) {
        this.ephemeralAccessKeyId = ephemeralAccessKeyId;
    }
    
    @Override
    public boolean validate() {
        if (ephemeralAccessKeyId && StringUtils.isEmpty(securityToken)) {
            return false;
        }
        return StringUtils.isNotBlank(super.getAccessKey()) && StringUtils.isNotBlank(super.getSecretKey());
    }
}
