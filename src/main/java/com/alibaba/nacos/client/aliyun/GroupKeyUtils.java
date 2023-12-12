package com.alibaba.nacos.client.aliyun;

public class GroupKeyUtils {
    public static String getGroupKey2(String dataId, String group) {
        StringBuilder sb = new StringBuilder();
        urlEncode(dataId, sb);
        sb.append('+');
        urlEncode(group, sb);
        return sb.toString();
    }
    
    public static void urlEncode(String str, StringBuilder sb) {
        for (int idx = 0; idx < str.length(); ++idx) {
            char c = str.charAt(idx);
            if ('+' == c) {
                sb.append("%2B");
            } else if ('%' == c) {
                sb.append("%25");
            } else {
                sb.append(c);
            }
        }
    }
    
    
}
