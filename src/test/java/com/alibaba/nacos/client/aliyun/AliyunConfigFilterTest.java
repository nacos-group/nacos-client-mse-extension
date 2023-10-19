package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.alibaba.nacos.client.config.filter.impl.ConfigFilterChainManager;
import com.alibaba.nacos.client.config.filter.impl.ConfigRequest;
import com.alibaba.nacos.client.config.filter.impl.ConfigResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class AliyunConfigFilterTest {
    private static final String ENCRYPTED_DATA_KEY = "encryptedDataKey";
    public static Properties properties;
    public static final List<String> dataIdList = new ArrayList<String>(){{
        add("cipher-crypt");
        add("cipher-kms-aes-256-crypt");
        add("cipher-kms-aes-128-crypt");
    }};

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
        properties.setProperty("regionId", "cn-beijing");
        properties.setProperty("kms_region_id", "cn-beijing");
        properties.setProperty("accessKey", "LTAxxxx1E6");
        properties.setProperty("secretKey", "kr6JxxxsD6");
        properties.setProperty("keyId", "alias/acs/mse");
        executeConfigFilter();
    }

    // must be running in vpc
//    @Test
//    public void testAliyunConfigFilterWithKmsV3() {
//        properties.setProperty(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv3.getValue());
//        properties.setProperty("keyId", "alias/chasu");
//        properties.setProperty("kmsEndpoint", "kst-bjxxxxxxxxxc.cryptoservice.kms.aliyuncs.com");
//        properties.setProperty("kmsClientKeyFilePath", "/client_key.json");
//        properties.setProperty("kmsPasswordKey", "19axxx213");
//        properties.setProperty("kmsCaFilePath", "/ca.pem");
//        executeConfigFilter();
//    }

    private void executeConfigFilter() {
        for (String dataId : dataIdList) {
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
            configResponse.setEncryptedDataKey((String) configRequest.getParameter(ENCRYPTED_DATA_KEY));
            configResponse.setContent(encryptedContent);
            try {
                configFilterChainManager.doFilter(null, configResponse);
                Assertions.assertEquals(content, configResponse.getContent());
            } catch (NacosException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
