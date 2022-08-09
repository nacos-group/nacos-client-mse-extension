package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.config.filter.AbstractConfigFilter;
import com.alibaba.nacos.api.config.filter.IConfigFilterChain;
import com.alibaba.nacos.api.config.filter.IConfigRequest;
import com.alibaba.nacos.api.config.filter.IConfigResponse;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.auth.AlibabaCloudCredentialsProvider;
import com.aliyuncs.auth.InstanceProfileCredentialsProvider;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.FormatType;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.http.ProtocolType;
import com.aliyuncs.kms.model.v20160120.DecryptRequest;
import com.aliyuncs.kms.model.v20160120.EncryptRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyRequest;
import com.aliyuncs.kms.model.v20160120.GenerateDataKeyResponse;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;

import java.util.Properties;

/**
 * the IConfigFilter of Aliyun.
 *
 * @author luyanbo(RobberPhex)
 */
public class AliyunConfigFilter extends AbstractConfigFilter {

    private static final String GROUP = "group";

    private static final String DATA_ID = "dataId";

    private static final String CONTENT = "content";

    private static final String REGION_ID = "regionId";
    
    private static final String KMS_REGION_ID = "kms_region_id";

    private static final String KEY_ID = "keyId";

    private static final String ENCRYPTED_DATA_KEY = "encryptedDataKey";

    private static final String CIPHER_PREFIX = "cipher-";

    public static final String CIPHER_KMS_AES_128_PREFIX = "cipher-kms-aes-128-";

    public static final String CIPHER_KMS_AES_256_PREFIX = "cipher-kms-aes-256-";

    public static final String KMS_KEY_SPEC_AES_128 = "AES_128";

    public static final String KMS_KEY_SPEC_AES_256 = "AES_256";

    private DefaultAcsClient kmsClient;

    private String keyId;

    @Override
    public void init(Properties properties) {
        keyId = properties.getProperty(KEY_ID);
        String regionId = properties.getProperty(REGION_ID);
        String ramRoleName = properties.getProperty(PropertyKeyConst.RAM_ROLE_NAME);
        String accessKey = properties.getProperty(PropertyKeyConst.ACCESS_KEY);
        String secretKey = properties.getProperty(PropertyKeyConst.SECRET_KEY);
        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT);
    
        if(StringUtils.isEmpty(regionId)){
            regionId = System.getProperty(KMS_REGION_ID, System.getenv(KMS_REGION_ID));
        }
        
        if (System.getProperties().containsKey(AliyunConst.KMS_ENDPOINT)) {
            kmsEndpoint = System.getProperty(AliyunConst.KMS_ENDPOINT);
        }
        if (!StringUtils.isBlank(kmsEndpoint)) {
            DefaultProfile.addEndpoint(regionId, "kms", kmsEndpoint);
        }
        IClientProfile profile = null;
        if (!StringUtils.isBlank(ramRoleName)) {
            profile = DefaultProfile.getProfile(regionId);
            AlibabaCloudCredentialsProvider alibabaCloudCredentialsProvider = new InstanceProfileCredentialsProvider(
                    ramRoleName);
            kmsClient = new DefaultAcsClient(profile, alibabaCloudCredentialsProvider);
        } else {
            profile = DefaultProfile.getProfile(regionId, accessKey, secretKey);
            kmsClient = new DefaultAcsClient(profile);
        }
    }

    @Override
    public void doFilter(IConfigRequest request, IConfigResponse response, IConfigFilterChain filterChain)
            throws NacosException {
        String dataId = null;
        String group = null;
        try {
            if (request != null) {
                dataId = (String) request.getParameter(DATA_ID);
                group = (String) request.getParameter(GROUP);
                if (dataId.startsWith(CIPHER_PREFIX)) {
                    if (request.getParameter(CONTENT) != null) {
                        request.putParameter(CONTENT, encrypt(keyId, request));
                    }
                }

                filterChain.doFilter(request, response);
            }
            if (response != null) {
                dataId = (String) response.getParameter("dataId");
                group = (String) response.getParameter("group");
                if (dataId.startsWith(CIPHER_PREFIX)) {
                    response.putParameter("content", decrypt(response));
                }
            }
        } catch (ClientException e) {
            e.printStackTrace();
            String message = String.format("KMS error, dataId: %s, groupId: %s", dataId, group);
            throw new NacosException(NacosException.HTTP_CLIENT_ERROR_CODE, message, e);
        } catch (Exception e) {
            NacosException ee = new NacosException();
            ee.setCauseThrowable(e);
            throw ee;
        }
    }

    private String decrypt(IConfigResponse response) throws Exception {
        String dataId = (String) response.getParameter("dataId");
        String content = (String) response.getParameter("content");
        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            String encryptedDataKey = (String) response.getParameter("encryptedDataKey");
            if (!StringUtils.isBlank(encryptedDataKey)) {
                String dataKey = decrypt(encryptedDataKey);
                return AesUtils.decrypt((String) response.getParameter("content"), dataKey, "UTF-8");
            }
            return "";
        } else {
            return decrypt(content);
        }
    }

    private String decrypt(String content) throws ClientException {
        final DecryptRequest decReq = new DecryptRequest();
        decReq.setSysProtocol(ProtocolType.HTTPS);
        decReq.setSysMethod(MethodType.POST);
        decReq.setAcceptFormat(FormatType.JSON);
        decReq.setCiphertextBlob(content);
        return kmsClient.getAcsResponse(decReq).getPlaintext();
    }

    private String encrypt(String keyId, IConfigRequest configRequest) throws Exception {
        String dataId = (String) configRequest.getParameter(DATA_ID);

        if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX) || dataId.startsWith(CIPHER_KMS_AES_256_PREFIX)) {
            String keySpec = null;
            if (dataId.startsWith(CIPHER_KMS_AES_128_PREFIX)) {
                keySpec = KMS_KEY_SPEC_AES_128;
            } else {
                keySpec = KMS_KEY_SPEC_AES_256;
            }
            GenerateDataKeyResponse generateDataKeyResponse = generateDataKey(keyId, keySpec);
            configRequest.putParameter(ENCRYPTED_DATA_KEY, generateDataKeyResponse.getCiphertextBlob());
            String dataKey = generateDataKeyResponse.getPlaintext();
            return AesUtils.encrypt((String) configRequest.getParameter(CONTENT), dataKey, "UTF-8");
        }

        return encrypt(keyId, (String) configRequest.getParameter(CONTENT));
    }
    
    private String encrypt(String keyId, String plainText) throws Exception {
        final EncryptRequest encReq = new EncryptRequest();
        encReq.setProtocol(ProtocolType.HTTPS);
        encReq.setAcceptFormat(FormatType.JSON);
        encReq.setMethod(MethodType.POST);
        encReq.setKeyId(keyId);
        encReq.setPlaintext(plainText);
        return kmsClient.getAcsResponse(encReq).getCiphertextBlob();
    }

    private GenerateDataKeyResponse generateDataKey(String keyId, String keySpec) throws ClientException {
        GenerateDataKeyRequest generateDataKeyRequest = new GenerateDataKeyRequest();

        generateDataKeyRequest.setAcceptFormat(FormatType.JSON);

        generateDataKeyRequest.setKeyId(keyId);
        generateDataKeyRequest.setKeySpec(keySpec);
        return kmsClient.getAcsResponse(generateDataKeyRequest);
    }

    @Override
    public int getOrder() {
        return 0;
    }

    @Override
    public String getFilterName() {
        return this.getClass().getName();
    }
}
