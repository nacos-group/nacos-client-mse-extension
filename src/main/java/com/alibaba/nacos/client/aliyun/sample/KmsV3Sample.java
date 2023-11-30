package com.alibaba.nacos.client.aliyun.sample;

import com.alibaba.nacos.api.NacosFactory;
import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.config.ConfigService;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.client.aliyun.AliyunConst;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class KmsV3Sample {
    public static Properties properties;

    public static final List<String> dataIdListPost = new ArrayList<String>(){{
        add("common-config");
        add("cipher-kms-aes-256-crypt");
    }};

    public static final String content = "crypt";

    public static final String group = "default";
    public static void main(String[] args) throws NacosException {
        properties = new Properties();
        properties.put(PropertyKeyConst.SERVER_ADDR, "serverAddr");
        properties.put(PropertyKeyConst.NAMESPACE, "ns");
        properties.put(PropertyKeyConst.ACCESS_KEY, "ak");
        properties.put(PropertyKeyConst.SECRET_KEY, "value of sk");
        
        properties.put(AliyunConst.REGION_ID, "value of regionId");
        properties.put(AliyunConst.KMS_REGION_ID, "value of kms_region_id");
        properties.put(AliyunConst.KMS_ENDPOINT, "value of kmsEndpoint");
        properties.put(AliyunConst.KEY_ID, "value of keyId");
        properties.put(AliyunConst.KMS_PASSWORD_KEY, "value of kmsPasswordKey");
        
        //only need set one between AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY and AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY
        properties.put(AliyunConst.KMS_CLIENT_KEY_CONTENT_KEY, "value of kmsClientKey");
//        properties.put(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY, "path to kmsClientKeyFile");
        
        //only need set one between AliyunConst.KMS_CA_FILE_CONTENT and AliyunConst.KMS_CA_FILE_PATH_KEY
        properties.put(AliyunConst.KMS_CA_FILE_CONTENT, "value of kmsCaFile");
//        properties.put(AliyunConst.KMS_CA_FILE_PATH_KEY, "path to kmsCaFile");
        
        properties.put(AliyunConst.KMS_VERSION_KEY, AliyunConst.KmsVersion.Kmsv3.getValue());
        ConfigService configService = NacosFactory.createConfigService(properties);

        //publish and get config
        System.out.println("------config loop------");
        for (String dataId : dataIdListPost) {
            boolean b = configService.publishConfig(dataId, group, content);
            if (!b) {
                System.out.println("publish config: dataId=" + dataId + ",publishConfig failed");
            } else {
                System.out.println("publish config: dataId=" + dataId + ",publishConfig success");
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            String content = configService.getConfig(dataId, group, 5000);
            System.out.println("get config: dataId=" + dataId + ",content=" + content);
        }
    }
}
