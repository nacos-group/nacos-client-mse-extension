package com.alibaba.nacos.client.aliyun;

import com.alibaba.nacos.api.utils.StringUtils;
import com.aliyuncs.exceptions.ClientException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class KmsUtils {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(KmsUtils.class);
    
    /**
     * KMS限流返回错误码
     */
    public final static String REJECTED_THROTTLING = "Rejected.Throttling";
    /**
     * KMS服务不可用返回错误码
     */
    public final static String SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary";
    /**
     * KMS服务内部错误返回错误码
     */
    public final static String INTERNAL_FAILURE = "InternalFailure";
    /**
     * KMS服务Socket连接超时错误码
     */
    public final static String SDK_READ_TIMEOUT = "SDK.ReadTimeout";
    
    /**
     * KMS服务无法连接错误码
     */
    public final static String SDK_SERVER_UNREACHABLE = "SDK.ServerUnreachable";
    
    /**
     * 根据Client异常判断是否进行规避重试
     *
     * @param e 指定Client异常
     * @return
     */
    public static boolean judgeNeedBackoff(ClientException e) {
        return REJECTED_THROTTLING.equals(e.getErrCode()) || SERVICE_UNAVAILABLE_TEMPORARY.equals(e.getErrCode())
                || INTERNAL_FAILURE.equals(e.getErrCode());
    }
    
    /**
     * 根据Client异常判断是否进行容灾重试
     *
     * @param e 指定Client异常
     * @return
     */
    public static boolean judgeNeedRecoveryException(ClientException e) {
        return SDK_READ_TIMEOUT.equals(e.getErrCode()) || SDK_SERVER_UNREACHABLE.equals(e.getErrCode())
                || judgeNeedBackoff(e);
    }
    
    public static int parsePropertyValue(Properties properties, String propertyName, int defaultValueInt) {
        String propertyValueString = properties.getProperty(propertyName, System.getProperty(propertyName, System.getenv(propertyName)));
        int resultValue = defaultValueInt;
        if (!StringUtils.isBlank(propertyValueString)) {
            try {
                resultValue = Integer.parseInt(propertyValueString);
            } catch (Exception e) {
                LOGGER.warn("parse {} failed: {}\n. use default value {}.", propertyName, e.getMessage(), defaultValueInt);
            }
        }
        return resultValue;
    }
    
    public static boolean parsePropertyValue(Properties properties, String propertyName, boolean defaultValueInt) {
        String propertyValueString = properties.getProperty(propertyName, System.getProperty(propertyName, System.getenv(propertyName)));
        boolean resultValue = defaultValueInt;
        if (!StringUtils.isBlank(propertyValueString)) {
            try {
                resultValue = Boolean.parseBoolean(propertyValueString);
            } catch (Exception e) {
                LOGGER.warn("parse {} failed: {}\n. use default value {}.", propertyName, e.getMessage(), defaultValueInt);
            }
        }
        return resultValue;
    }
    
}
