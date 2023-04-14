#coding:utf-8
from __future__ import print_function
from xml.etree import ElementTree
from datetime import datetime
from collections import OrderedDict
import sys
import re
import time
import os
if sys.version_info.major < 3:
    import httplib 
else:
    import http.client as httplib

# 定义调用RESTful API的类，该类中定义了一些方法来执行建立HTTP连接时的操作。该部分无需修改，用户可以直接使用。
# 该部分可以直接调用，用户不需要修改。
class OPSConnection(object):
    """Make an OPS connection instance."""

    # 初始化类，创建一个HTTP连接。
    def __init__(self, host, port = 80):
        self.host = host
        self.port = port
        self.headers = {
            "Content-type": "text/xml",
            "Accept":       "text/xml"
            }
        self.conn = None

    # 关闭HTTP连接。
    def close(self):
        """Close the connection"""
        self.conn.close()

    # 创建设备资源操作。
    def create(self, uri, req_data):
        """Create operation"""
        ret = self.rest_call("POST", uri, req_data)
        return ret

    # 删除设备资源操作。
    def delete(self, uri, req_data):
        """Delete operation"""
        ret = self.rest_call("DELETE", uri, req_data)
        return ret

    # 查询设备资源操作。
    def get(self, uri, req_data = None):
        """Get operation"""
        ret = self.rest_call("GET", uri, req_data)
        return ret

    # 修改设备资源操作。
    def set(self, uri, req_data):
        """Set operation"""
        ret = self.rest_call("PUT", uri, req_data)
        return ret

    # 类内部调用的方法。
    def rest_call(self, method, uri, req_data):
        """REST call"""
        if req_data == None:
            body = ""
        else:
            body = req_data
        if self.conn:
            self.conn.close()
        self.conn = httplib.HTTPConnection(self.host, self.port)
        self.conn.request(method, uri, body, self.headers)
        response = self.conn.getresponse()
        response.status = httplib.OK    # stub code
        abc = response.read()
        #print(abc)
        abc = xmlParse(abc)
        ret = (response.status, response.reason, abc)
        #print('HTTP/1.1 %s %s\n\n%s' % ret)
        return ret

def delping(ops_conn,DIP):
    uri = "/dgntl/ipv4/deleteIpPing"
    # 指定发送的请求内容。该部分内容与URI相对应，不同的URI对应不同的请求内容。
    # 用户需要根据实际使用的URI对请求内容进行修改，关于请求内容的格式可参考RESTful API。
    req_data = \
'''<?xml version="1.0" encoding="UTF-8"?>
          <deleteIpPing>
            <testName>127.0.0.1</testName>
          </deleteIpPing>
''' 
    req_int = ElementTree.fromstring(req_data)
    req_int.find('testName').text = str(DIP)
    req_format = ElementTree.tostring(req_int)
    ret, _, rsp_data = ops_conn.set(uri, req_format)
    if ret != httplib.OK:
        return None
    return rsp_data


# 定义ping
def ping(ops_conn,DIP,Count,interval='',SIP='',Psize='',timeout='1000',vrfName='',notFragment='false'):

    # 指定系统启动信息的URI。URI为Resetful API中定义的管理对象，不同的管理对象有不同的URI。
    # 用户需要根据实际需求对URI进行修改，关于设备支持的URI可参考RESTful API。
    uri3 = "/dgntl/ipv4/startIpPing"

    # 指定发送的请求内容。该部分内容与URI相对应，不同的URI对应不同的请求内容。
    # 用户需要根据实际使用的URI对请求内容进行修改，关于请求内容的格式可参考RESTful API。
    req_data3 = \
'''<?xml version="1.0" encoding="UTF-8"?>
          <startIpPing>
            <testName>127.0.0.1</testName>
            <destAddr>127.0.0.1</destAddr>
            <sourceAddr></sourceAddr>
            <packetCount>10</packetCount>
            <packetSize></packetSize>
            <interval></interval>
            <timeout></timeout>
            <vrfName></vrfName>
            <notFragmentFlag></notFragmentFlag>
          </startIpPing>
'''
    # 用户可以根据实际需求对请求类型get()进行修改，例如修改为set()或者create()。
    #ret, _, rsp_data = ops_conn.create(uri3, req_data3)
    req_int = ElementTree.fromstring(req_data3)
    req_int.find('testName').text = str(DIP)
    req_int.find('destAddr').text = str(DIP)
    req_int.find('sourceAddr').text = str(SIP)
    req_int.find('packetCount').text = str(Count)
    req_int.find('packetSize').text = str(Psize)
    req_int.find('interval').text = str(interval)
    req_int.find('timeout').text = str(timeout)
    req_int.find('vrfName').text = str(vrfName)
    req_int.find('notFragmentFlag').text = str(notFragment)
    req_format = ElementTree.tostring(req_int)
    ret, _, rsp_data = ops_conn.create(uri3, req_format)
    if ret != httplib.OK:
        return None

    return rsp_data

def getRes(ops_conn,lastping_res):

    # 指定系统启动信息的URI。URI为Resetful API中定义的管理对象，不同的管理对象有不同的URI。
    # 用户需要根据实际需求对URI进行修改，关于设备支持的URI可参考RESTful API。
    uri2 = "/dgntl/ipv4/ipv4PingResults"

    # 指定发送的请求内容。该部分内容与URI相对应，不同的URI对应不同的请求内容。
    # 用户需要根据实际使用的URI对请求内容进行修改，关于请求内容的格式可参考RESTful API。
    req_data2 = \
'''<?xml version='1.0' encoding='UTF-8'?>  
<ipv4PingResults>
    <ipv4PingResult>
       <testName></testName> 
       <packetRecv/> 
       <packetSend/> 
       <lossRatio/> 
       <rttMin/> 
       <rttMax/> 
       <averageRtt/> 
       <status/> 
       <errorType/> 
    </ipv4PingResult>
</ipv4PingResults> 
'''

    # 用户可以根据实际需求对请求类型get()进行修改，例如修改为set()或者create()。
    ret, _, rsp_data = ops_conn.get(uri2, req_data2)
    if ret != httplib.OK:
        return None
    del rsp_data['rpc-reply']
    del rsp_data['data']
    del rsp_data['dgntl']
    del rsp_data['ipv4']
    del rsp_data['ipv4PingResults']
    del rsp_data['ipv4PingResult']
    del rsp_data['errorType']
    print("-----------------------------------------------------------------------------------------------------")
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'))
    print("-----------------------------------------------------------------------------------------------------",end=' ')
    listTitle = ['Host','Recv','Send','Loss','Mix','Max','Avg','Progress','Status']
    printList = list(chunks(list(rsp_data.values()),8))
    for i in listTitle:
        if i  == listTitle[0] :
            print("\n%-17s"%i,end=' ')
        else:
            print("%-10s"%i,end=' ')

    for i,l in zip(printList,lastping_res):
        i[3] = int(i[2]) - int(i[1])
        if i[2] == l[2]:
            i.append('-')
        elif (i[3] == l[3]) and (int(i[1]) > int(l[1])):
            i.append('Normal')
        elif (i[3] == l[3]) and (int(i[1]) == int(l[1])):
            i.append(l[8])
        else:
            i.append('Failed')
        for j in i:
            if j == i[0]:
                print("\n%-17s"%j,end=' ')
            else:
                print("%-10s"%j,end=' ')
    print()
    return printList


def xmlParse(xmlstr):
    xml_parse = ElementTree.fromstring(xmlstr)
    prefix = ''
    dictkey = []
    dictvalue = []
    for node in xml_parse.iter():
        if node.tag == "{http://www.huawei.com/netconf/vrp}testName":
            prefix = node.text
        elif node.tag == "{http://www.huawei.com/netconf/vrp}errorType":
            prefix = ''
        dictkey.append(str(prefix)+str(node.tag.split('}')[-1]))
        dictvalue.append(node.text)
    data = OrderedDict(zip(dictkey,dictvalue))
    #data = dict([(node.tag.split('}')[-1],node.text) for node in xml_parse.iter()])
    return data


def check_ip(ipAddr):
    compile_ip=re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if compile_ip.match(ipAddr):
        return True 
    else:  
        return False

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]
def merge(l):
    j = []
    for i in l:
        j = j + i
    return j

def pinginput(n):
    if sys.version_info.major < 3:
        return raw_input(n)
    else:
        return input(n)

def main():
    """The main function."""
    # host表示环路地址，目前RESTful API仅支持设备内部调用，即取值为“localhost”。
    host = "localhost"
    status = ['processing']
    SIP = []
    IPinput = []
    print('''===========================================xPing=====================================================\n*Ctrl + C to Break\n=====================================================================================================''')
    interval = pinginput('Interval(500) :')
    Count =    pinginput('PacketCount(5):')
    Psize =    pinginput('PacketSize(56):')
    timeout =  pinginput('Timeout(1000) :')
    notFragment =  pinginput('NotFragment(false) :')
    print("*DestAddr VrfName SourceAddr(:q Start)")
    
    while True:
        IPinput = list(pinginput("").split())
        if IPinput:
            if IPinput[0] == ':q':
                break
            else:
                if check_ip(IPinput[0]):
                    SIP.append(IPinput)
    print("Start ping task，Ctrl + C to Break")
    ping_res = [[0]*9]*len(SIP)
    try:
        # 建立HTTP连接。
        ops_conn = OPSConnection(host)
        
        for i in SIP:
            if len(i) == 1:
                rsp_del = delping(ops_conn,i[0])
                rsp_data = ping(ops_conn,i[0],Count,interval,Psize=Psize,timeout=timeout,notFragment=notFragment)
            elif len(i) == 2:
                rsp_del = delping(ops_conn,i[0])
                rsp_data = ping(ops_conn,i[0],Count,interval,Psize=Psize,timeout=timeout,vrfName=i[1],notFragment=notFragment)
            elif len(i) == 3:
                rsp_del = delping(ops_conn,i[0])
                rsp_data = ping(ops_conn,i[0],Count,interval,SIP=i[2],Psize=Psize,timeout=timeout,vrfName=i[1],notFragment=notFragment)
            else:
                print("No Tasks!")

        while 'processing' in status:
            #os.system('clear')
            time.sleep(0.2)
            ping_res = getRes(ops_conn,ping_res)
            status = merge(ping_res)

        for i in SIP:
            if len(i) == 1:
                rsp_del = delping(ops_conn,i[0])
            elif len(i) == 2:
                rsp_del = delping(ops_conn,i[0])
            else:
                print("No Tasks!")
        print("Tips: Tasks All Done!")
        # 关闭HTTP连接。
        ops_conn.close()
        return

    except KeyboardInterrupt:
        for i in SIP:
            if len(i) == 1:
                rsp_del = delping(ops_conn,i[0])
            elif len(i) == 2:
                rsp_del = delping(ops_conn,i[0])
            else:
                print("No Tasks!")
        print("Tips: Tasks Break!")
        return

    except Exception as e:
        print("\nError")
        print(e)
        return

if __name__ == "__main__":
    main()
