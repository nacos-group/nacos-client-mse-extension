package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.config.filter.AbstractConfigFilter;
import com.alibaba.nacos.api.config.filter.IConfigFilterChain;
import com.alibaba.nacos.api.config.filter.IConfigRequest;
import com.alibaba.nacos.api.config.filter.IConfigResponse;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyun.dkms.gcs.openapi.models.Config;
import com.aliyun.kms.KmsTransferAcsClient;
import com.aliyuncs.IAcsClient;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

/**
 * the IConfigFilter of Aliyun.
 *
 * @author luyanbo(RobberPhex)
 */
public class AliyunConfigFilter extends AbstractConfigFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AliyunConfigFilter.class);

    private static final String GROUP = "group";

    private static final String DATA_ID = "dataId";

    private static final String CONTENT = "content";

    private static final String REGION_ID = "regionId";
    
    private static final String KMS_REGION_ID = "kms_region_id";

    private static final String KEY_ID = "keyId";

    private static final String ENCRYPTED_DATA_KEY = "encryptedDataKey";

    private static final String CIPHER_PREFIX = "cipher-";

    private static AliyunConst.KmsVersion kmsVersion;

    public static final String CIPHER_KMS_AES_128_PREFIX = "cipher-kms-aes-128-";

    public static final String CIPHER_KMS_AES_256_PREFIX = "cipher-kms-aes-256-";

    public static final String KMS_KEY_SPEC_AES_128 = "AES_128";

    public static final String KMS_KEY_SPEC_AES_256 = "AES_256";

    private IAcsClient kmsClient;

    private String keyId;

    @Override
    public void init(Properties properties) {
        LOGGER.info("init ConfigFilter: {}, for more information, please check: {}",
                this.getFilterName(), AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
        // get kms version, default using kms v1
        String kv = properties.getProperty(AliyunConst.KMS_VERSION_KEY);
        if (StringUtils.isBlank(kv)) {
            LOGGER.warn("kms version is not set, using kms v1 version.");
            kmsVersion = AliyunConst.KmsVersion.Kmsv1;
        } else {
            kmsVersion = AliyunConst.KmsVersion.fromValue(kv);
            if (kmsVersion == AliyunConst.KmsVersion.UNKNOWN_VERSION) {
                LOGGER.warn("kms version is not supported, using kms v1 version.");
                kmsVersion = AliyunConst.KmsVersion.Kmsv1;
            } else {
                LOGGER.info("using kms version {}.", kmsVersion.getValue());
            }
        }

        //keyId corresponding to the id/alias of KMS's secret key, using mseServiceKeyId by default
        keyId = properties.getProperty(KEY_ID);
        if (StringUtils.isBlank(keyId)) {
            if (kmsVersion == AliyunConst.KmsVersion.Kmsv1) {
                keyId = AliyunConst.KMS_DEFAULT_KEY_ID_VALUE;
                LOGGER.info("using default keyId {}.", keyId);
            } else {
                LOGGER.error("keyId is not set up yet, unable to encrypt the configuration. " +
                        "For more information, please check: {}", AliyunConst.MSE_ENCRYPTED_CONFIG_USAGE_DOCUMENT_URL);
            }
        }

        try {
            if (kmsVersion == AliyunConst.KmsVersion.Kmsv1) {
                kmsClient = createKmsV1Client(properties);
            } else if (kmsVersion == AliyunConst.KmsVersion.Kmsv3) {
                kmsClient = createKmsV3Client(properties);
            }
        } catch (ClientException e) {
            LOGGER.error("create kms client failed.");
        }
    }

    /**
    * init kms v1 client, accessing the KMS service through a shared gateway.
    *
    * @date 2023/9/19
    * @description
    * @param properties
    * @return com.aliyuncs.IAcsClient
    * @throws
    */
    private IAcsClient createKmsV1Client(Properties properties) {
        String regionId = properties.getProperty(REGION_ID);
        if (StringUtils.isBlank(regionId)) {
            regionId = System.getProperty(KMS_REGION_ID, System.getenv(KMS_REGION_ID));
        }
        LOGGER.info("using regionId {}.", regionId);

        String ramRoleName = properties.getProperty(PropertyKeyConst.RAM_ROLE_NAME);
        LOGGER.info("using ramRoleName {}.", ramRoleName);

        String accessKey = properties.getProperty(PropertyKeyConst.ACCESS_KEY);
        LOGGER.info("using accessKey {}.", accessKey);

        String secretKey = properties.getProperty(PropertyKeyConst.SECRET_KEY);

        String kmsEndpoint = System.getProperties().containsKey(AliyunConst.KMS_ENDPOINT) ?
                System.getProperty(AliyunConst.KMS_ENDPOINT) : properties.getProperty(AliyunConst.KMS_ENDPOINT);
        if (!StringUtils.isBlank(kmsEndpoint)) {
            DefaultProfile.addEndpoint(regionId, "kms", kmsEndpoint);
        }
        LOGGER.info("using kmsEndpoint {}.", kmsEndpoint);

        IClientProfile profile = null;
        IAcsClient kmsClient = null;
        if (!StringUtils.isBlank(ramRoleName)) {
            profile = DefaultProfile.getProfile(regionId);
            AlibabaCloudCredentialsProvider alibabaCloudCredentialsProvider = new InstanceProfileCredentialsProvider(
                    ramRoleName);
            kmsClient = new KmsTransferAcsClient(profile, alibabaCloudCredentialsProvider);
            LOGGER.info("successfully create kms client by using RAM role.");
        } else {
            profile = DefaultProfile.getProfile(regionId, accessKey, secretKey);
            kmsClient = new KmsTransferAcsClient(profile);
            LOGGER.info("successfully create kms client by using ak/sk.");
        }
        return kmsClient;
    }

    /**
    * init kms v3 client, accessing the KMS service through the KMS instance gateway.
    *
    * @date 2023/9/19
    * @description
    * @param properties
    * @return 
    * @throws 
    */
    private IAcsClient createKmsV3Client(Properties properties) throws ClientException {
        Config config = new Config();
        config.setProtocol("https");

        String kmsClientKeyFilePath = properties.getProperty(AliyunConst.KMS_CLIENT_KEY_FILE_PATH_KEY);
        LOGGER.info("using kmsClientKeyFilePath: {}.", kmsClientKeyFilePath);
        config.setClientKeyFile(kmsClientKeyFilePath);
        //config.setClientKeyContent(kmsClientKeyContent);

        String kmsEndpoint = properties.getProperty(AliyunConst.KMS_ENDPOINT);
        LOGGER.info("using kmsEndpoint: {}.", kmsEndpoint);
        config.setEndpoint(kmsEndpoint);

        String kmsPassword = properties.getProperty(AliyunConst.KMS_PASSWORD_KEY);
        LOGGER.info("using kmsPassword: {}.", kmsPassword);
        config.setPassword(kmsPassword);

        String kmsCaFilePath = properties.getProperty(AliyunConst.KMS_CA_FILE_PATH_KEY);
        LOGGER.info("using kmsCaFilePath: {}.", kmsCaFilePath);
        config.setCaFilePath(kmsCaFilePath);
        //config.setCa(caContent);

        return new KmsTransferAcsClient(config);
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
