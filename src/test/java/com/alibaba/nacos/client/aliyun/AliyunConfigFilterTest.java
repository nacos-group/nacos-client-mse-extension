package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.config.filter.impl.ConfigFilterChainManager;
import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Properties;

public class AliyunConfigFilterTest {
    public static Properties properties;
    public static final String dataId = "cipher-crypt";

    public static final String content = "crypt";

    public static final String group = "default";

    @BeforeEach
    public void preset() {
        try {
            properties = new Properties();
            properties.load(this.getClass().getResourceAsStream("/aliyun-kms.properties"));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testAliyunConfigFilterWithKmsV1() {
        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv1.getValue());
        //ignore kmsEndpoint
        properties.setProperty("kmsEndpoint", "");
        executeConfigFilter();
    }

    // must be running in vpc
//    @Test
//    public void testAliyunConfigFilterWithKmsV3() {
//        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv1.getValue());
//        properties.setProperty("keyId", "alias/chasu");
//        executeConfigFilter();
//    }

    private void executeConfigFilter() {
        ConfigFilterChainManager configFilterChainManager = new ConfigFilterChainManager(properties);
        AliyunConfigFilter aliyunConfigFilter = new AliyunConfigFilter();
        configFilterChainManager.addFilter(aliyunConfigFilter);

        ConfigRequest configRequest = new ConfigRequest();
        configRequest.setGroup(group);
        configRequest.setDataId(dataId);
        configRequest.setContent(content);
        String encryptedContent = null;
        try {
            configFilterChainManager.doFilter(configRequest, null);
            encryptedContent = configRequest.getContent();
            Assertions.assertFalse(StringUtils.isBlank(encryptedContent));
        } catch (NacosException e) {
            e.printStackTrace();
        }

        ConfigResponse configResponse = new ConfigResponse();
        configResponse.setGroup(group);
        configResponse.setDataId(dataId);
        configResponse.setContent(encryptedContent);
        try {
            configFilterChainManager.doFilter(null, configResponse);
            Assertions.assertEquals(content, configResponse.getContent());
        } catch (NacosException e) {
            throw new RuntimeException(e);
        }
    }
}
