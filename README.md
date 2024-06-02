# bt_webshell_scan


宝塔（www.bt.cn）自带的查杀功能太差劲了，搞不定webshell，重写了一下查杀规则，主要功能包括: `白名单`、`河马查杀（河马误报太高暂停接入）`、`自写查杀引擎`。 使用场景是宝塔安装搭建好之后，覆盖插的文件（覆盖目录：/www/server/panel/plugin/webshell_check）



### 功能清单

- [x] php webshell扫描
- [x] 查看webshell代码
- [x] 白名单








**查杀引擎**

针对php的webshell进行扫描，对于上传代码，各类webshell木马和混淆加密的木马有较好的识别。




## 安装

安装宝塔后，安装“木马查杀工具”，然后上传代码覆盖“/www/server/panel/plugin/webshell_check”。


## 致谢
感谢宝塔官方，木马查杀工具是在官方UI基础上进行了修改，只为优化查杀准确率。

https://www.bt.cn/
