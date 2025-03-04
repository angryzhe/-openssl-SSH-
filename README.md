# 基于openssl实现远程SSH登录的国密改造

[](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:openssh)基于openssl实现远程SSH登录的国密改造

- [基于openssl实现远程SSH登录的国密改造](#%E5%9F%BA%E4%BA%8Eopenssl%E5%AE%9E%E7%8E%B0%E8%BF%9C%E7%A8%8Bssh%E7%99%BB%E5%BD%95%E7%9A%84%E5%9B%BD%E5%AF%86%E6%94%B9%E9%80%A0)
    - [目标描述](#%E7%9B%AE%E6%A0%87%E6%8F%8F%E8%BF%B0)
        - [第一题：基本的环境搭建和熟悉](#%E7%AC%AC%E4%B8%80%E9%A2%98%E5%9F%BA%E6%9C%AC%E7%9A%84%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA%E5%92%8C%E7%86%9F%E6%82%89)
        - [第二题：将openssl提供算法库中的sm3/sm4国密算法适配到openssh中](#%E7%AC%AC%E4%BA%8C%E9%A2%98%E5%B0%86openssl%E6%8F%90%E4%BE%9B%E7%AE%97%E6%B3%95%E5%BA%93%E4%B8%AD%E7%9A%84sm3sm4%E5%9B%BD%E5%AF%86%E7%AE%97%E6%B3%95%E9%80%82%E9%85%8D%E5%88%B0openssh%E4%B8%AD)
        - [第三题：将openssl提供算法库中的sm2国密算法适配到openssh中](#%E7%AC%AC%E4%B8%89%E9%A2%98%E5%B0%86openssl%E6%8F%90%E4%BE%9B%E7%AE%97%E6%B3%95%E5%BA%93%E4%B8%AD%E7%9A%84sm2%E5%9B%BD%E5%AF%86%E7%AE%97%E6%B3%95%E9%80%82%E9%85%8D%E5%88%B0openssh%E4%B8%AD)
    - [比赛题目分析和相关资料调研](#%E6%AF%94%E8%B5%9B%E9%A2%98%E7%9B%AE%E5%88%86%E6%9E%90%E5%92%8C%E7%9B%B8%E5%85%B3%E8%B5%84%E6%96%99%E8%B0%83%E7%A0%94)
        - [第一题](#%E7%AC%AC%E4%B8%80%E9%A2%98)
        - [第二题](#%E7%AC%AC%E4%BA%8C%E9%A2%98)
        - [第三题](#%E7%AC%AC%E4%B8%89%E9%A2%98)
        - [资料调研](#%E8%B5%84%E6%96%99%E8%B0%83%E7%A0%94)
    - [解题过程](#%E8%A7%A3%E9%A2%98%E8%BF%87%E7%A8%8B)
        - [第一题](#%E7%AC%AC%E4%B8%80%E9%A2%98-2)
        - [第二题](#%E7%AC%AC%E4%BA%8C%E9%A2%98-2)
        - [第三题](#%E7%AC%AC%E4%B8%89%E9%A2%98-2)
    - [开发计划](#%E5%BC%80%E5%8F%91%E8%AE%A1%E5%88%92)
    - [比赛过程中的重要进展](#%E6%AF%94%E8%B5%9B%E8%BF%87%E7%A8%8B%E4%B8%AD%E7%9A%84%E9%87%8D%E8%A6%81%E8%BF%9B%E5%B1%95)
    - [系统测试情况](#%E7%B3%BB%E7%BB%9F%E6%B5%8B%E8%AF%95%E6%83%85%E5%86%B5)
        - [测试方案](#%E6%B5%8B%E8%AF%95%E6%96%B9%E6%A1%88)
        - [测试结果](#%E6%B5%8B%E8%AF%95%E7%BB%93%E6%9E%9C)
    - [遇到的主要问题和解决方法](#%E9%81%87%E5%88%B0%E7%9A%84%E4%B8%BB%E8%A6%81%E9%97%AE%E9%A2%98%E5%92%8C%E8%A7%A3%E5%86%B3%E6%96%B9%E6%B3%95)
    - [分工和协作](#%E5%88%86%E5%B7%A5%E5%92%8C%E5%8D%8F%E4%BD%9C)
    - [提交仓库目录和文件描述](#%E6%8F%90%E4%BA%A4%E4%BB%93%E5%BA%93%E7%9B%AE%E5%BD%95%E5%92%8C%E6%96%87%E4%BB%B6%E6%8F%8F%E8%BF%B0)
    - [比赛收获](#%E6%AF%94%E8%B5%9B%E6%94%B6%E8%8E%B7)
- [Portable OpenSSH](#portable-openssh)
    - [Documentation](#documentation)
    - [Stable Releases](#stable-releases)
    - [Building Portable OpenSSH](#building-portable-openssh)
        - [Dependencies](#dependencies)
        - [Building a release](#building-a-release)
        - [Building from git](#building-from-git)
        - [Build-time Customisation](#build-time-customisation)
    - [Development](#development)
    - [Reporting bugs](#reporting-bugs)

## 目标描述

#### 第一题：基本的环境搭建和熟悉

- 在linux系统上编译并运行openssh社区的openssh-8.8p1，也可以使用openEuler系统上的openssh-8.8p1-1.oe1源码编译。
- 修改openssh的配置文件，使用各类支持的密钥交换、公钥认证、完整性认证、对称加密算法进行SSH登录， 初步比较各类算法的性能。

#### 第二题：将openssl提供算法库中的sm3/sm4国密算法适配到openssh中

- 在openssh的完整性认证mac中加入hmac-sm3算法，并能够通过配置这种算法登录；
- 在openssh的对称加密算法cipher中加入sm4-ctr算法，并能够通过配置这种算法登录；

#### 第三题：将openssl提供算法库中的sm2国密算法适配到openssh中

- 适配ssh-keygen和ssh-keyscan命令，使它们能够生成和扫描sm2类型的密钥；
- 在openssh的公钥认证算法pubkeyacceptedkeytypes中加入sm2算法，并能够使用sm2密钥进行登录；
- 在openssh的密钥交换算法中加入sm2dh算法，并能够使用这种密钥交换算法进行登录；

## 比赛题目分析和相关资料调研

#### 第一题

**1.1**这题的关键在于配置好运行环境，openssh配置相对繁琐，尤其是要更改或者升级openssh，由于更新openssh操作不经常在Ubuntu此类Linux系统上进行，所以需要下载必要的软件包——例如：yum，rpm，zlib1g-dev等。请注意，若删除openssh，一般会连带着snap和相关包（包括ubuntu-software及从上面下载的软件）。不过snap其实并不好用，所以不用担心，只需将其他软件重新用apt下载回来即可。这部分可参考：  
https://www.cnblogs.com/98record/p/bian-yi-an-zhuang-sheng-jiopenssh-zui-xin-ban.html  
https://www.cnblogs.com/maxzhangxiaotao/p/17388467.html

![删除原openssh会连带一些文件删除.png](/_resources/e4713583d4d7c7805c22a503e1d6504c.png)


**1.2** 要了解openssh的文件分类和主要配置文件，比如可以修改/etc/ssh/ssh_config文件,设置不同的Host条目,运用不同的加密算法；可以添加不同密钥到~/.ssh/authorized_keys文件,用于不同Host的登录等等。如果想要检查SSH服务端（sshd）支持的算法，需要直接查看sshd的配置文件sshd_config，或者使用特定的命令或工具来查询sshd服务的配置。。

#### 第二题

了解openssh的文件分类和不同文件的功能；对源码中的cipher.c和mac.c等文件进行阅读和了解，发现需要根据已有结构体定义增加加密算法条目。我们还需要查阅密码的算法文档，充分了解hmac-sm3和sm4-ctr算法，并添加参数至代码中。

#### 第三题

根据题目的提示：

- 适配ssh-keygen和ssh-keyscan命令，使它们能够生成和扫描sm2类型的密钥；
- 在openssh的公钥认证算法pubkeyacceptedkeytypes中加入sm2算法，并能够使用sm2密钥进行登录；
- 在openssh的密钥交换算法中加入sm2dh算法，并能够使用这种密钥交换算法进行登录；

可以得到较为清晰的解决思路。了解到在OpenSSH中,公钥认证算法由 **/etc/ssh/sshd_config**和\*\*~/.ssh/authorized_keys\*\*两个主要文件控制，所以可能主要对这两个文件进行相应的修改。

而密钥交换算法由/etc/ssh/sshd_config文件中的KexAlgorithms选项控制。

#### 资料调研

SM4 文档：[国家标准|GB/T 32907-2016 (samr.gov.cn)](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=7803DE42D3BC5E80B0C3E5D8E873D56A)

SM3文档：[国家标准|GB/T 32905-2016 (samr.gov.cn)](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=45B1A67F20F3BF339211C391E9278F5E)

SM2文档：[国家标准|GB/T 35276-2017 (samr.gov.cn)](https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=2127A9F19CB5D7F20D17D334ECA63EE5)

OpenSSH的源码和相关手册：[OpenSSH](https://www.openssh.com/) [OpenSSH: Portable Release](https://www.openssh.com/portable.html)

目前主要完成了第一题、第二题和第三题的设计

## **解题过程**

* * *

#### **第一题**

**1.编译OpenSSL和Zlib两个依赖库**

1.1编译OpenSSL依赖库。

OpenSSL是一个开源的网络安全工具包,用于实现SSL/TLS协议，主要功能包含：SSL/TLS协议实现、加密算法实现、密钥和证书生成、hash算法实现。由于提供了这些广泛且成熟的加密和安全功能,OpenSSL已成为许多应用实现网络安全的首选工具包或基础库。但有个问题是：openssh每个版本均有与其适配的openssl版本。在这里我们需要匹配其版本号，不过原则上来说不同版本也可使用，只要需要注意openssh里不同文件所调用的变量与函数名字，因为openssl会一直更新。

```
wget https://www.openssl.org/source/openssl-1.1.1u.tar.gz
tar -xf openssl-1.1.1m.tar.gz
```

使用tar解压后进行预编译和编译安装：

```
./config --prefix=/usr/local/openssl shared
make
make install 
```

1.2编译Zlib依赖库

zlib是一套通用的解压缩开源库，提供了内存（in-memory）压缩和解压函数，能检测解压出来的数据完整性。它实现了流行的DEFLATE压缩算法,常用于网络传输和存储。主要功能包含：提供DEFLATE压缩/解压缩算法实现、支持zlib格式、gzip格式以及raw DEFLATE格式、提供压缩级别选项,允许在压缩比和压缩速度之间进行权衡、提供各语言软件包,方便在各种语言和系统中集成等功能。OpenSSH、OpenSSL也会运用zlib来达到最佳化加密网络传输。在ubuntu中要安装zlib1g-dev才可进行下一步的编译，所以我们可以输入：

```
sudo apt-get install zlib1g-dev
```

在使用DEbian时，还需要安装libz-dev。libz-dev包含Zlib的开发文件,满足开发和编译需要;声明对运行时环境的依赖,确保环境完备;并遵循Debian的软件包管理规范,可以很好的与Debian的软件包体系协同工作：

```
sudo apt -y install libz-dev
```

**2.更换编译OpenSSH**

2.1.下载Openssh-8.8p1并使用taz解压：

```
wget https://mirror.leaseweb.com/pub/OpenBSD/OpenSSH/portable/openssh-8.8p1.tar.gz
tar -xf openssh-8.8p1.tar.gz
```

2.2.编译安装Openssh-8.8p1

```
./configure --prefix=/usr/local/openssh --sysconfdir=/etc/ssh  --with-ssl-dir=/usr/local/openssl --with-zlib-dir=/usr/local/zlib --without-openssl-header-check
make
make install
#创建软链接
ln -s /usr/local/openssh/sbin/sshd /sbin/sshd
ln -s /usr/local/openssh/bin/ssh /usr/bin/ssh
ln -s /usr/local/openssh/bin/ssh-add /usr/bin/ssh-add
ln -s /usr/local/openssh/bin/ssh-keygen /usr/bin/ssh-keygen
ln -s /usr/local/openssh/bin/ssh-keyscan /usr/bin/ssh-keyscan
```

2.3启动OpenSSH

```
# 检查现在的ssh版本
ssh -V
# 修改默认配置，允许root登录
vi /etc/ssh/sshd_config
#将 #PermitRootLogin prohibit-password 修改为 PermitRootLogin yes
# 将sshd服务设为开机启动
chkconfig sshd on
```

#### **第二题**

1.  在cipher.c文件中添加一行
    
    ```
    { "sm4-ctr",16, 24, 0, 0, 0, EVP_sm4_ctr }
    ```
    
    添加此算法后,OpenSSH将支持SM4-CTR模式进行数据加密,用户可以在ssh_config 或 sshd_config配置文件中使用加密算法sm4-ctr。
    
    例如,在客户端配置文件~/.ssh/config中:
    
    ```
    Ciphers sm4-ctr
    ```
    
    这会将SM4-CTR模式设置为首选的加密算法。然后当OpenSSH建立连接时,如果服务器也支持sm4-ctr算法,双方将使用该算法进行数据加密通信。所以,添加这一行实现了在OpenSSH中添加对SM4-CTR算法的支持,支持使用SM4国密算法进行加密通信。
    
2.  OpenSSL的digest-openssl.c文件可以为OpenSSH提供一个统一的摘要算法接口。该文件实现的接口抽象了OpenSSL的各种摘要算法, 使OpenSSH的其他部分可以通过统一的函数调用使用不同的摘要算法。
    
    所以我们在**const struct ssh_digest digests\[\] 数组**（定义了OpenSSH支持的各种摘要算法），中加入
    
    ```
    { SSH_DIGEST_SM3, "SM3", 32, EVP_sm3 }
    ```
    
    于是就为OpenSSH加入了hmac-sm3算法。
    
3.  由于OpenSSH的digest.h头文件主要定义了与摘要算法相关的接口和数据结构，所以里面的部分内容也需要进行修改。SSH_DIGEST_MAX宏定义了OpenSSH支持的最大摘要算法数，所以对其进行修改，增加1
    
    ```
    #define SSH_DIGEST_MAX		6
    ```
    
    同时增加一个宏定义
    
    ```
    #define SSH_DIGEST_SM3      5
    ```
    
    指定上述加入的摘要函数id为5
    
4.  根据题目要求，我们还需要修改mac.c文件，其中，macalg结构体定义了OpenSSH支持的各种消息认证码算法。mac_algorithms数组的元素就是macalg结构,用于定义每个支持的MAC算法。我们在数组中加上
    
    ```
    { "hmac-sm3-128@openssh.com",  SSH_DIGEST, SSH_DIGEST_SM3, 0, 0, 0, 0},
    ```
    
    各字段含义如下:
    
    - &lt;algo_name&gt;: MAC算法的名称,在这里是"hmac-sm3-128@openssh.com"。
    - \-MAC_ALGO_TYPE: 算法类型,这里是SSH_DIGEST,表示基于HMAC构造的摘要算法。
    - SSH_DIGEST_XXX: 所使用的具体摘要算法,这里是SSH_DIGEST_SM3,所以该MAC算法使用HMAC-SM3。
    - KEY_LEN_MIN: 算法支持的最小密钥长度,这里是0,表示不限制。
    - KEY_LEN_MAX: 算法支持的最大密钥长度,这里也是0,不限制。
    - CTX_LEN: MAC算法上下文结构体的大小,这里是0。
    - DO_INIT_FN: 是否需要调用init函数初始化上下文,这里是0, 不需要调用。

    也加上另一个相似的字段

    ```
    { "hmac-sm3-128etm@openssh.com",      SSH_DIGEST, SSH_DIGEST_SM3, 0, 0, 0, 1},
    ```

    是一样的加密算法，但是加密强度不同

#### **第三题**

第三题虽说是只提到了适配ssh-keygen和ssh-keyscan命令，但涉及到的代码文件繁多。在这里所采用的openssh版本是8.8p1，但在此之后openssh就进行了一次大的版本更新，与此同时openssl同时从1.X版本更新为3.X版本。所以在这里我们将与时俱进，在主题不变的情况下对书写风格进行更改。

1.  列表项在Makefile.in文件中的LIBSSH_OBJS变量定义中修改增加：

    ```
    LIBSSH_OBJS=${LIBOPENSSH_OBJS} \
    ...
    monitor_fdpass.o rijndael.o ssh-dss.o ssh-ecdsa.o ssh-sm2.o ssh-ecdsa-sk.o \
    ...
    kex.o kexdh.o kexgex.o kexecdh.o kexc25519.o kexsm2.o \
    ```

    这些对象文件是构建OpenSSH库的一部分，它们被编译和链接在一起，以创建最终的库文件。所以我们把`ssh-sm2.o`和`kexsm2.o`加进去以便编译。

2.  列表项在 authfd.c的ssh_add_identity_constrained函数（用于在SSH代理中添加一个受限的私钥）中

    ```
    switch (key->type) {
     ...
    +	case KEY_SM2:
    +	case KEY_SM2_CERT:
    ```

    这个添加的作用主要是函数可根据私钥的类型（通过key->type获取）来确定要发送的消息类型。支持的私钥类型添加了SM2以及其证书版本
&nbsp;
    同时在authfile.c文件中的sshkey_load_private_cert函数上也添加：

```
   case KEY_SM2:
```

3.  在kax.c文件中的kexalgs的静态常量数组中添加：

    ```
    
    { "sm2-sm3", KEX_SM2_SM3, NID_sm2, SSH_DIGEST_SM3 },
    ```

    在这里：
	- char \*name: 密钥交换算法的名称。
	-  int kex_type: 密钥交换算法的内部标识符。
	-  int group_type: 与密钥交换算法相关的群组类型，如果是0，则表示不使用特定的群组。
	-  int hash_alg: 与密钥交换算法相关的哈希算法标识符
&nbsp;
    同时在kex.h中的enum kex_exchange添加：

    ```
    KEX_SM2_SM3;
    ```

4.  在kexgen.c文件中的kex_gen_client函数添加：

    ```
    case KEX_SM2_SM3:
        r = kex_ecdh_keypair(kex);
           break;
    ```

    它的作用是生成SSH客户端的密钥对，并发送公钥到服务器以开始密钥交换过程，使用switch语句根据kex->kex_type的值来确定使用哪种密钥交换算法。对于基于椭圆曲线Diffie-Hellman（ECDH）的算法，调用kex_ecdh_keypair。因为SM2为非对称加密，基于ECC，所以我们可以调用这个函数来实现这个功能。同时在input_kex_gen_reply函数里添加`case KEX_SM2_SM3:`。
&nbsp;
5.  在文件pathnames.h里添加：

    ```
    #define _PATH_SSH_CLIENT_ID_SM2         _PATH_SSH_USER_DIR "/id_sm2"
    ```

    这里主要是关于SSH客户端认证密钥文件的默认路径的定义。在SSH协议中，客户端通常需要使用私钥文件来验证其身份，这些私钥文件与特定的公钥算法相对应。`_PATH_SSH_CLIENT_ID_SM2`: 定义了SM2私钥文件的默认路径。这些私钥文件的路径都是相对于用户目录的，例如：\_PATH_SSH_CLIENT_ID_SM2将指向/home/username/.ssh/id_sm2 。
&nbsp;
6.  在ssh-ecdsa.c中的ssh_ecdsa_sign和ssh_ecdsa_verify两个函数中添加(带+的是添加的代码)：

    ```
    if (key == NULL || key->ecdsa == NULL ||
    //sshkey_type_plain(key->type) != KEY_ECDSA)
        + (sshkey_type_plain(key->type) != KEY_ECDSA &&
         + sshkey_type_plain(key->type) != KEY_SM2) ||
        return SSH_ERR_INVALID_ARGUMENT;
    ```

    这个条件检查密钥的类型是否为KEY_ECDSA或者KEY_SM2。sshkey_type_plain函数可能是用来获取密钥的基础类型，这里它被用来确保密钥是ECDSA或SM2类型。 return SSH_ERR_INVALID_ARGUMENT; 如果上面的条件检查为真，即输入参数无效，函数将返回一个错误码SSH_ERR_INVALID_ARGUMENT，表示调用者提供了无效的参数。
&nbsp;
7.  在文件ssh-keygen.c中的type_bits_valid函数里添加（带+的为添加的代码）：

     ```
    case KEY_ECDSA:
    + case KEY_SM2:
    ....
    case KEY_SM2:
        if (*bitsp != 256)
            fatal("Invalid SM2 key length: must be 256 bits");
    ```

    这个函数里有三个参数:
	- int type: 密钥类型。
	- const char \*name: 密钥的名称或曲线名称。
	- u_int32_t \*bitsp: 指向存储密钥位数的指针。

	第一个添加的意思是：如果 bitsp 指向的位数值为 0，则根据密钥类型设置默认位数对于 KEY_ECDSA 或 KEY_SM2，首先尝试根据名称获取对应的椭圆曲线 nid（通过 sshkey_ecdsa_nid_from_name 函数），然后转换为位数（通过 sshkey_curve_nid_to_bits 函数）。如果失败，则设置为 DEFAULT_BITS_ECDSA。
&nbsp;
	对于每种密钥类型，验证 bitsp 指向的位数是否有效：对于 KEY_SM2，位数必须为 256 位。
&nbsp;
8.  在ssh-keygen.c中的ask_filename函数中添加：

	```
    case KEY_SM2:
            name = _PATH_SSH_CLIENT_ID_SM2;
            break;
    ```

	其作用是提示用户输入一个文件名，通常用于选择私钥文件。对于SM2密钥类型，name 指向 \_PATH_SSH_CLIENT_ID_SM2
&nbsp;
9.  在ssh-keygen.c中的do_convert_to_pkcs8 函数中添加：

	```
    case KEY_ECDSA:
    + case KEY_SM2:
    ```

	其作用是将私钥转换为PKCS#8格式并输出 ,对于 KEY_ECDSA 和 KEY_SM2 类型的密钥，使用 PEM_write_EC_PUBKEY 函数。 对于do_convert_to_pem函数也是如此。
&nbsp;
10. 在ssh-keygen.c中的usage中添加：

    ```
    [-t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa | sm2]\n
    ```

	用于输出 ssh-keygen 命令的使用说明。由于ssh-keygen 是 OpenSSH 套件中的一个工具，用于生成新的 SSH 密钥对，并对现有密钥进行管理，所以我们可以在这里看到很多操作。在这里改为\[-t type\]: 指定要生成的密钥类型，支持 dsa, ecdsa, ecdsa-sk, ed25519, ed25519-sk, rsa, 和 sm2。

11. 在ssh-keyscan.c先添加
    ```
	    + #define KT_SM2 (1<<7)
    + #define KT_MAX KT_SM2
    ```
&nbsp;
	再在 keygrab_ssh2 函数中添加：
   ```
   case KT_SM2:
  myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = get_cert ?
                  "sm2-cert-v01@openssh.com" :
                  "sm2";
              break;
  ....
  c->c_ssh->kex->kex[KEX_SM2_SM3] = kex_gen_client;
   ```

此函数应该是用来设置 SSH 连接中使用的密钥交换算法提案的。函数接收一个参数 con \*c，这是一个指向连接（con）结构的指针，该结构可能包含了有关当前连接的信息，比如密钥类型等。对于 KT_SM2 密钥类型，提案字符串根据 get_cert 的值选择 “sm2-cert-v01@openssh.com” 或 “sm2”。而下面那行代码的作用是将SM2-SM3密钥交换算法的客户端生成函数kex_gen_client赋给当前SSH连接对象的密钥交换方法数组中对应的位置。这样，在SSH连接建立过程中，如果协商选择了SM2-SM3作为密钥交换算法，就会调用kex_gen_client函数来生成密钥。

然后再main函数中的tname循环里的type分支中加：

```
    case KEY_SM2:
      get_keytypes |= KT_SM2;
      break;
```

12. 在ssh_api.c文件中的ssh_init 函数中增加：

    ```
    ssh->kex->kex[KEX_SM2_SM3] = kex_gen_server;
    ....
    ssh->kex->kex[KEX_SM2_SM3] = kex_gen_client;
    ```

    这个函数用于初始化 SSH 连接并准备密钥交换。根据 is_server 的值，为服务器端或客户端分别设置不同的密钥交换算法函数指针（对于 KEX_SM2_SM3 算法也如此）。例如：
	- 对于服务器端，使用 kex_gen_server 作为生成密钥的函数。
	- 对于客户端，使用 kex_gen_client 作为生成密钥的函数。
&nbsp;

13. 在sshd.c文件中的list_hostkey_types函数、get_hostkey_by_type函数和main函数中添加(前面数字为行数)：

    ```
    634:  case KEY_SM2:
    656:  case KEY_SM2_CERT:
    700:  case KEY_SM2:
    702:  case KEY_SM2_CERT;
    1890: case KEY_SM2;
    2411: kex->kex[KEX_SM2_SM3] = kex_gen_server;
    ```

	list_hostkey_types函数的作用是列出支持的SSH主机密钥类型。如果密钥存在，则根据密钥的类型（key->type），使用append_hostkey_type函数将对应的SSH密钥名称添加到缓冲区b中。在这          里如果是SM2类型密钥则直接使用sshkey_ssh_name(key)函数获取其SSH名称并添加。如果存在对应的认证密钥（存储在sensitive_data.host_certificates数组中），则同样根据认证密钥的类型添        加相应的SSH名称。
&nbsp;
	get_hostkey_by_type函数用于根据指定的密钥类型、曲线NID（如果适用）和是否需要私钥标志来检索主机密钥。先根据密钥类型选择密钥，添加的代码意思是如果请求的是SM2，则从 sensitive_data.host_certificates数组中检索对应索引的密钥。之后再检查曲线NID（如果适用）对于ECDSA和SM2类型的密钥，还需要检查密钥的曲线NID（key->ecdsa_nid）是否与请求的NID匹配。如果NID不匹配，则继续下一次循环。
&nbsp;
14. 在sshkey.h文件中的enum sshkey_types添加

    ```
    KEY_SM2,
    KEY_SM2_CERT,
    ```

	再添加声明：`sshkey_names_valid2(char*, int, int);`
&nbsp;
15. 对于sshkey.c文件改动很大，我们要先知道8.x的版本和9.x版本的这个文件代码大不一样，9.x版本代码更简洁，阅读性、可修改性更好，逻辑更清晰。所以在这里我们将代码书写风格改为9.x风格。先添加：

    ```
    +extern const struct sshkey_impl sshkey_sm2_impl;
    +extern const struct sshkey_impl sshkey_sm2_cert_impl;
    ```

	且在const struct sshkey_impl \* const keyimpls\[\] (它包含了指向不同 sshkey_impl 结构体实例的指针。这些结构体实例代表各种类型的SSH密钥实现) 中添加：

    ```
    + &sshkey_sm2_impl,
    + &sshkey_sm2_cert_impl,
    ```

	在 key_type_is_ecdsa_variant函数（其作用是判断给定的密钥类型是否为ECDSA变体）中添加：

    ```
    + case KEY_SM2:
    + case KEY_SM2_CERT:
    ```

	在sshkey_type_plain和sshkey_type_certified函数添加：

    ```
    + case KEY_SM2_CERT:
        + return KEY_SM2;
    ....
    + case KEY_SM2:
        + return KEY_SM2_CERT;
    ```

	 在sshkey_curve_name_to_nid函数中添加

    ```
    else if (strcmp(name, "sm2") == 0)
      return NID_sm2;
    ```

	再限定SM2位数（sshkey_curve_nid_to_bit函数中）：

    ```
    + case NID_sm2:
        + return 256;
    ```

	在sshconnect2.c中的ssh_kex2函数（用于在 SSH连接中启动密钥交换过程）中添加

    ```
    ssh->kex->kex[KEX_SM2_SM3] = kex_gen_client;
    ```

	通过这行代码，当SSH客户端需要使用SM2_SM3密钥交换算法时，它会调用 kex_gen_client 函数来执行密钥生成和交换的客户端部分。这是SSH协议中建立安全连接的一个关键步骤，确保了客户端和服务器之间可以安全地交换数据。
&nbsp;
16. 编写kexsm2.c文件，它实现了使用SM2椭圆曲线密码学算法的SSH密钥交换（key exchange）功能。文件中包含了几个关键函数，它们的主要功能如下：
	- sm2_compute_z_digest: 此函数用于计算Z值的摘要，这是SM2密钥交换过程中的一个步骤。它接受输入参数如摘要算法、标识符（ID）、标识符长度、EC_KEY（椭圆曲线密钥）等，并输出计算得到的摘要。
	- kdf_gmt003_2012: 这个函数实现了GM/T 003-2012密钥衍生函数（Key Derivation Function, KDF），用于从共享的秘密Z和其他信息中派生出密钥材料。
	- sm2_kap_compute_key: 该函数用于计算SM2密钥交换过程中的密钥。它考虑了服务器和客户端的不同情况，使用了用户ID、对等椭圆曲线密钥、公钥等作为输入，并输出派生出的密钥。
	- SM2KAP_compute_key: 这个函数是一个简化的接口，用于计算密钥。它创建了一个新的SM2公钥，并使用固定的ID来调用sm2_kap_compute_key函数。
&nbsp;
	kexsm2.c 文件提供了一套完整的、符合SM2标准的密钥交换实现，用于在SSH协议中安全地建立加密通信。该文件的编写可以参考kexc25519.c等文件，这些文件实现效果类似，只是算法不同。
&nbsp;
17. 编写ssh-sm2.c 文件。这个文件的核心功能是为 SSH 实现提供 SM2 密钥算法的支持。以下是该文件的关键组成部分及其功能：
	- 密钥清理 (ssh_sm2_cleanup): 释放与 SM2 密钥关联的资源。
	- 密钥比较 (ssh_sm2_equal): 比较两个 SM2 密钥是否相同。
	- 公钥序列化与反序列化 (ssh_sm2_serialize_public, ssh_sm2_deserialize_public): 分别用于将 SM2 公钥序列化为字节流和从字节流中恢复 SM2 公钥。
	- 私钥序列化与反序列化 (ssh_sm2_serialize_private, ssh_sm2_deserialize_private): 分别用于将 SM2 私钥序列化为字节流和从字节流中恢复 SM2 私钥。
	- 密钥生成 (ssh_sm2_generate): 生成新的 SM2 密钥对。
	- 公钥复制 (ssh_sm2_copy_public): 复制 SM2 公钥从一个密钥结构到另一个。
	- 签名生成辅助函数 (sm2_get_sig): 辅助函数，用于获取 SM2 签名。
	- 签名 (ssh_sm2_sign): 实现 SM2 签名算法，用于创建数据的数字签名。
	- 签名验证辅助函数 (sm2_verify_sig): 辅助函数，用于验证 SM2 签名的有效性。
	- 签名验证 (ssh_sm2_verify): 实现 SM2 签名验证算法，用于检验数字签名的真实性。
	- 密钥操作函数集 (sshkey_sm2_funcs): 定义了 SM2 密钥的一系列操作函数，包括清理、比较、序列化、生成、复制、签名和验证等。
	- 密钥实现结构体 (sshkey_sm2_impl, sshkey_sm2_cert_impl): 分别定义了 SM2 密钥和 SM2 证书密钥的实现结构体，包含了密钥名称、类型、NID（对象标识符）、证书标志、签名标志、密钥位数和指向密钥操作函数集的指针。
&nbsp;
    这个文件通过提供这些功能，使得 SSH 客户端和服务器能够使用 SM2 算法进行安全通信。值得一说的是，该文件的编写可参考ssh-ed25519.c等文件，这些文件实现效果都类似，只是算法不一样。




## 开发计划

阶段一：5.5~5.15 确定整体设计思路，完成较为简单的几个问题；设计测试方案；

阶段二：5.16~5.23 完成整体问题，实现测试；

阶段三：5.24~5.31 进一步完善项目要求和测试，形成完整文档。

## 比赛过程中的重要进展

1.  在Ubuntu中完成了openssh-8.8p1的环境配置和初步运行；
2.  在openssh的完整性认证mac中加入hmac-sm3算法，并进行了代码调试；
3.  在openssh的对称加密算法cipher中加入sm4-ctr算法，并进行了代码调试；
4.  适配了ssh-keygen和ssh-keyscan命令，试它们能够生成和扫描sm2类型的密钥；
5.  在openssh的公钥认证算法pubkeyacceptedkeytypes中加入sm2算法，并能够使用sm2密钥进行登录；
6.  在openssh的密钥交换算法中加入sm2dh算法，并能够使用这种密钥交换算法进行登录；

## 系统测试情况

#### 测试方案

**功能测试**:测试OpenSSH的所有功能选项、命令以及主要功能是否正常工作。这包括:

SSH客户端/服务器的连接与验证测试  
\-各种认证方式的测试:密码、公钥等  
\- SSHTunnel、端口转发等功能的测试  
\- SCP、SFTP等子命令的测试  
\- SSH配置选项的测试:KexAlgorithms、Ciphers等

**集成测试**:在regress目录下,有很多脚本用于测试OpenSSH各种功能的集成效果,如登录、文件传输、端口转发等。这些测试脚本可以在多种环境下运行,测试OpenSSH在不同系统和配置下的行为。

**性能测试**:在regress目录下也有一些脚本用于测试OpenSSH的性能,如scp的传输速度等。这可以评估OpenSSH各版本之间的性能差异和改进。

**兼容性测试**:有测试脚本专门用于测试OpenSSH对多种SSH协议和标准的兼容性,确保OpenSSH兼容广泛的SSH客户端和服务器实现。

**代码覆盖测试**:使用gcc的gcov工具检查每个测试用例覆盖的OpenSSH源码行数,确保测试的覆盖范围较高和完整。

**Ed25519证书测试**:随着Ed25519证书的支持,有相关的测试脚本,可以测试Ed25519证书的生成、使用和校验等功能。这可以确保Ed25519证书的支持没有引入问题。

&nbsp;
### 一、验证OpenSSH是否支持国密算法
#### 测试结果
- 输入此命令来查询支持的算法：
    ```
    ssh -Q PubkeyAcceptedAlgorithms

    ```
	![支持的算法.png](/_resources/c4d8b03213e97f21e71f50e0a40f2b9a.png)

	可以看到支持SM2算法
	&nbsp;
### 二、创建SSH国密sm2密钥对
- 输入：
    ```
	ssh-keygen -t sm2 -m PEM -f /etc/ssh/ssh_host_sm2_key

    ```
	- [ ssh-keygen ] 用于生成SSH密钥对;
	- [ -t sm2 ] 指定加密算法为国密sm2;
	- [ -m PEM ] 指定私钥文件格式为PEM;
	- [ -f /etc/ssh/ssh_host_sm2_key ] 指定密钥对文件生成后所存储的路径.
&nbsp;
   为了方便测试，我们这里不输入自定义字符串 作为 passphrase（实际生活中是很危险的行为）
   ![生成SM2密钥对.png](/_resources/cbab75e27f9bb86d224a807c09a06d03.png)
&nbsp;
- 我们再打开一个新终端：
    ```
	sudo su root
	cd /etc/ssh
	ls
    ```
![已生成密钥对.png](/_resources/11a6c6bffb8809e9788587631e413533.png)
&nbsp;
- 生成SSH客户端密钥对
    ```
	ssh-keygen -t sm2 -m PEM
    ```
    随后，终端会要求您输入密钥对文件的保存位置可以直接按回车，保存到默认路径,这时passphrase也是空。
	![生成SSH客户端密钥对.png](/_resources/f6577b1378efbda58fa36e1172e96755.png)
&nbsp;
### 三、客户端利用sm2公钥完成服务端的ssh登录
查看pub文件：
```
cd /root/.ssh
ls
cat id_sm2.pub
```
 ![查看pub文件.png](/_resources/65214aeebbb66c035dbccc96494ab777.png)
&nbsp;
- 将pub公钥值放入ssh-server的/root/.ssh/authorized_keys，再创建ssh连接
    ```
	ssh   -o PreferredAuthentications=publickey -o HostKeyAlgorithms=sm2 -o PubkeyAcceptedKeyTypes=sm2 -o Ciphers=sm4-ctr -o MACs=hmac-sm3 -o KexAlgorithms=sm2-sm3 -i ~/.ssh/id_sm2 <username>@<IPadress>
    ```
## 遇到的主要问题和解决方法

1.工作初期，团队使用Ubuntu来对openssh进行装载。在装载过程中，遇到多种软件包的依赖关系模糊，导致装载进程缓慢。
&nbsp;
    **解决方案**：虽然Ubuntu对于更换openssh和openssh的使用不友好，但是由于操作成熟、发展时间长，只要查询网络很多问题都可以解决。

&nbsp;
2.进行SM4-CTR加密算法插入时，在cipher.c文件中较难定位具体的插入位置，导致SM4算法加入失败：
&nbsp;
     **解决方案**：通过研读Openssh开发文档及多次对cipher.c文件的尝试插入，最终从理论和实践上确定了SM4-CTR加密算法的插入位置，并在客户端配置文件~/.ssh/config中写入 Cipher.c sm4-ctr，完成了SM4算法的加入。
&nbsp;
3. 加入sm2算法的时候，难以定位在哪个文件的哪个位置写什么样的代码。
&nbsp;
**解决方案**：参考openssh原有的算法，例如ed25519算法。查看这些算法的代码，并在完成sm2算法要求的情况下模仿书写。

## 分工和协作

王哲：在openssh的完整性认证mac中加入hmac-sm3算法；在openssh的对称加密算法cipher中加入sm4-ctr算法；适配ssh-keygen和ssh-keyscan命令，使它们能够生成和扫描sm2类型的密钥；在openssh的公钥认证算法pubkeyacceptedkeytypes中加入sm2算法；文档整理

吴子航：在openssh的完整性认证mac中加入hmac-sm3算法；在openssh的对称加密算法cipher中加入sm4-ctr算法；团队文档的整理和搜集、完成openssh在Linux系统上的装载和调试。

## 提交仓库目录和文件描述

/…/

## 比赛收获

1.对Openssh有了进一步的了解，掌握了Openssh的Linux环境搭建，能够使用密钥交换、公钥认证、完整性认证、对称加密算法等算法进行SSH登录的方法。

2.初步学习了SM2、SM3、SM4三种国密算法的相关知识，对于完整性认证mac、对称加密算法cipher、公钥认证算法pubkeyacceptedkeytypes的实现有了一定认识。

3.在学习国密算法的同时，了解到国密算法在操作系统、网络设备、通信系统、商务应用,特别是涉及电子政务、电子商务等需要密码保护的应用系统上的应用，对网络安全方面有了认知。

# Portable OpenSSH

OpenSSH is a complete implementation of the SSH protocol (version 2) for secure remote login, command execution and file transfer. It includes a client `ssh` and server `sshd`, file transfer utilities `scp` and `sftp` as well as tools for key generation (`ssh-keygen`), run-time key storage (`ssh-agent`) and a number of supporting programs.

This is a port of OpenBSD’s [OpenSSH](https://openssh.com) to most Unix-like operating systems, including Linux, OS X and Cygwin. Portable OpenSSH polyfills OpenBSD APIs that are not available elsewhere, adds sshd sandboxing for more operating systems and includes support for OS-native authentication and auditing (e.g. using PAM).

## Documentation

The official documentation for OpenSSH are the man pages for each tool:

- [ssh(1)](https://man.openbsd.org/ssh.1)
- [sshd(8)](https://man.openbsd.org/sshd.8)
- [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)
- [ssh-agent(1)](https://man.openbsd.org/ssh-agent.1)
- [scp(1)](https://man.openbsd.org/scp.1)
- [sftp(1)](https://man.openbsd.org/sftp.1)
- [ssh-keyscan(8)](https://man.openbsd.org/ssh-keyscan.8)
- [sftp-server(8)](https://man.openbsd.org/sftp-server.8)

## Stable Releases

Stable release tarballs are available from a number of [download mirrors](https://www.openssh.com/portable.html#downloads). We recommend the use of a stable release for most users. Please read the [release notes](https://www.openssh.com/releasenotes.html) for details of recent changes and potential incompatibilities.

## Building Portable OpenSSH

### Dependencies

Portable OpenSSH is built using autoconf and make. It requires a working C compiler, standard library and headers.

`libcrypto` from either [LibreSSL](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org) may also be used, but OpenSSH may be built without it supporting a subset of crypto algorithms.

[zlib](https://www.zlib.net/) is optional; without it transport compression is not supported.

FIDO security token support needs [libfido2](https://github.com/Yubico/libfido2) and its dependencies. Also, certain platforms and build-time options may require additional dependencies; see README.platform for details.

### Building a release

Releases include a pre-built copy of the `configure` script and may be built using:

```
tar zxvf openssh-X.YpZ.tar.gz
cd openssh
./configure # [options]
make && make tests
```

See the [Build-time Customisation](#build-time-customisation) section below for configure options. If you plan on installing OpenSSH to your system, then you will usually want to specify destination paths.

### Building from git

If building from git, you’ll need [autoconf](https://www.gnu.org/software/autoconf/) installed to build the `configure` script. The following commands will check out and build portable OpenSSH from git:

```
git clone https://github.com/openssh/openssh-portable # or https://anongit.mindrot.org/openssh.git
cd openssh-portable
autoreconf
./configure
make && make tests
```

### Build-time Customisation

There are many build-time customisation options available. All Autoconf destination path flags (e.g. `--prefix`) are supported (and are usually required if you want to install OpenSSH).

For a full list of available flags, run `configure --help` but a few of the more frequently-used ones are described below. Some of these flags will require additional libraries and/or headers be installed.

| Flag | Meaning |
| --- | --- |
| `--with-pam` | Enable [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) support. [OpenPAM](https://www.openpam.org/), [Linux PAM](http://www.linux-pam.org/) and Solaris PAM are supported. |
| `--with-libedit` | Enable [libedit](https://www.thrysoee.dk/editline/) support for sftp. |
| `--with-kerberos5` | Enable Kerberos/GSSAPI support. Both [Heimdal](https://www.h5l.org/) and [MIT](https://web.mit.edu/kerberos/) Kerberos implementations are supported. |
| `--with-selinux` | Enable [SELinux](https://en.wikipedia.org/wiki/Security-Enhanced_Linux) support. |
| `--with-security-key-builtin` | Include built-in support for U2F/FIDO2 security keys. This requires [libfido2](https://github.com/Yubico/libfido2) be installed. |

## Development

Portable OpenSSH development is discussed on the [openssh-unix-dev mailing list](https://lists.mindrot.org/mailman/listinfo/openssh-unix-dev) ([archive mirror](https://marc.info/?l=openssh-unix-dev)). Bugs and feature requests are tracked on our [Bugzilla](https://bugzilla.mindrot.org/).

## Reporting bugs

*Non-security* bugs may be reported to the developers via [Bugzilla](https://bugzilla.mindrot.org/) or via the mailing list above. Security bugs should be reported to [openssh@openssh.com](mailto:openssh.openssh.com).