package com.alibaba.nacos.client.aliyun;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LocalTest {

    @Test
    public void testLocal() throws Exception {
        String commonCipherContent = AesUtils.encrypt("common cipher content", "6QSdvMf3ivYADypZejz2OQTX7EYc0+9750MoHGnVOJk=", "UTF-8");
        String commonCipherContent1 = AesUtils.encrypt("common cipher content", "6QSdvMf3ivYADypZejz2OQTX7EYc0+9750MoHGnVOJk=", "UTF-8");
        Assertions.assertEquals(commonCipherContent1, commonCipherContent);
    }
}
