# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 x7
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2017 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: lkqiang<lkq@bt.cn>
# +-------------------------------------------------------------------
# |   webshell 扫描插件
# +--------------------------------------------------------------------
import sys
if not '/www/server/panel/class/' in sys.path:
    sys.path.insert(0, '/www/server/panel/class/')
import json, os, time, public, string, re, hashlib,requests,subprocess,panelTask
class webshell_check_main:
    __count=0
    __size="/www/server/panel/plugin/webshell_check/size.txt"
    __shell="/www/server/panel/plugin/webshell_check/shell.txt"
    __shella="/www/server/panel/plugin/webshell_check/log.txt"
    __whitelist="/www/server/panel/plugin/webshell_check/whitelist.txt"
    __user={}

    def __init__(self):
        try:
            self.__user = json.loads(public.ReadFile('/www/server/panel/data/userInfo.json'))
        except:
            pass



    '''
    @name 获取目录下的所有php文件
    @param path 文件目录
    @return list 
    '''
    def get_dir(self, path):
        return_data = []
        data2 = []
        [[return_data.append(os.path.join(root, file)) for file in files] for root, dirs, files in os.walk(path)]
        for i in return_data:
            if str(i.lower())[-4:] == '.php':
                data2.append(i)
        return data2

    '''
    @name 读取文件内容
    @param filename 文件路径
    @return 文件内容
    '''
    def ReadFile(self,filename, mode='rb'):
        import os
        if not os.path.exists(filename): return False
        try:
            fp = open(filename, mode)
            f_body = fp.read()
            fp.close()
        except Exception as ex:
            if sys.version_info[0] != 2:
                try:
                    fp = open(filename, mode, encoding="utf-8")
                    f_body = fp.read()
                    fp.close()
                except Exception as ex2:
                    return False
            else:
                return False
        return f_body

    '''
    @name 获取文件的md5值
    @param filename 文件路径
    @return MD5
    '''
    def read_file_md5(self, filename):
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                content = f.read()
            m = hashlib.md5()
            m.update(content)
            return m.hexdigest()
        else:
            return False
        

    '''
    @name 上传到云端判断是否是webshell
    @param filename 文件路径
    @param url 云端URL
    @return bool 
    '''
    def webshellchop(self,filename,url):
        try:
            upload_url =url
            size = os.path.getsize(filename)
            if size > 1024000: return False
            if len(self.__user)==0:return  False
            md5=self.read_file_md5(filename)
            #shell_insert={'filename':filename,"type":"start","md5": md5}
            #self.syslogcc(shell_insert)
            file_type=self.Intelligence_engine(filename)
            print('file_type',file_type)
            #self.syslogcc(filename+"       file_type:"+file_type)
            if file_type!='':
               # self.syslogcc(filename+'文件为木马')
                print('%s文件为木马  md5:%s' % (filename,md5))
                shell_insert={'filename':filename,"md5": md5,"file_type":file_type}
                if os.path.exists(self.__shell):
                    public.WriteFile(self.__shell,json.dumps(shell_insert)+"\n","a+")
                else:
                    public.WriteFile(self.__shell,json.dumps(shell_insert)+"\n")
                print('%s可疑文件,建议手工检查' % filename)
                return True
            return False
            
            
            
            
            upload_data = {'inputfile': self.ReadFile(filename), "md5":md5,"path":filename,"access_key": self.__user['access_key'], "uid": self.__user['uid'],"username":self.__user["username"]}
            upload_res = requests.post(upload_url, upload_data, timeout=20).json()
            self.syslogcc(upload_res)
            if upload_res['msg']=='ok':
                if (upload_res['data']['data']['level']==5):
                    print('%s文件为木马  hash:%s' % (filename,upload_res['data']['data']['hash']))
                    shell_insert={'filename':filename,"md5":upload_res['data']['data']['hash']}
                    if os.path.exists(self.__shell):
                        public.WriteFile(self.__shell,json.dumps(shell_insert)+"\n","a+")
                    else:
                        public.WriteFile(self.__shell,json.dumps(shell_insert)+"\n")
                    return True
                else:
                     file_type=self.Intelligence_engine(filename)
                     if len(file_type)>=1:
                         self.syslogcc(filename+'文件为木马')
                         print('%s文件为木马  md5:%s' % (filename,md5))
                         shell_insert={'filename':filename,"md5": md5}
                         if os.path.exists(self.__shell):
                             public.WriteFile(self.__shell,json.dumps(shell_insert)+"\n","a+")
                         else:
                             public.WriteFile(self.__shell,json.dumps(shell_insert)+"\n")
                         print('%s可疑文件,建议手工检查' % filename)
                         return True
                     return False
                return False
            return False
        except:
            return False
    '''
    @name 上传到宝塔云端
    @param filename 文件路径
    @return bool 
    '''
    def send_baota2(self, filename):
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_submit'
        pdata = {'codetxt': self.ReadFile(filename), 'md5': self.read_file_md5(filename), 'type': '0',
                 'host_ip': public.GetLocalIp(), 'size': os.path.getsize(filename)}
        ret = public.httpPost(cloudUrl, pdata)
        return True
        
    '''    
    @name 启发查杀
    @param filename 文件路径
    @return string 
    '''
    def Intelligence_engine(self,filename):
        #self.syslogcc(filename)
        php_code=public.ReadFile(filename)
        md5_hash = self.read_file_md5(filename)
        with open(self.__whitelist, 'r', encoding='utf-8') as file:
            content = file.read()
            if md5_hash  in content:
                return ''
        if self.is_php_code_obfuscated(filename)==True:
            #self.syslogcc(filename+"   is_php_code_obfuscated")
            suspect=4
            rule="confuse,"
            
            #规则精准命中
            if '$_FILES' in php_code:
                if '<form' in php_code:
                     return 'php.webshell.uploaded'
                     
            if self.check_for_variable_functionsB(php_code)==True:
                if 'eval' in php_code:
                     return 'php.webshell.execute.'
                     
            pattern = r'<\?php\s+include\s*\(\s*[\'"](?P<filename>[^"\']*\.jpg)[\'"]\s*\)\s*;\s*\?>'
            matches = re.findall(pattern, php_code)
            for match in matches:
                return 'php.webshell.jpg'
            
            if 'eval' in php_code:
                rule=rule+'eval(,'
                suspect=suspect+2
            elif 'call_user_func_array' in php_code:
                rule=rule+'call_user_func_array,'
                suspect=suspect+2
            elif 'function_exists' in php_code:
                rule=rule+'function_exists,'
                suspect=suspect+2
            elif 'call_user_func' in php_code:
                rule=rule+'call_user_func,'
                suspect=suspect+2

                    
            
            
            
            if 'phpjiami.com' in php_code:
                rule=rule+'phpjiami.com,'
                suspect=suspect+3
            
            if 'PHPJiaMi.Com' in php_code:
                rule=rule+'phpjiami.com,'
                suspect=suspect+3
            
            if 'namespace' in php_code:
                rule=rule+'namespace'
                suspect=suspect-2
            
            if '\n' not in content:
                rule=rule+'none\n'
                suspect=suspect+2


            if  self.contains_complex_strings(php_code)==True:
                rule=rule+'Encrypted Content'
                #发现加密内容
                suspect=suspect+2

            if 'http://thinkphp.cn All rights reserved' in php_code:
                rule=rule+'http://thinkphp.cn,'
                suspect=suspect-2
            

            if 'require_once' in php_code:
                rule=rule+'require_once,'
                suspect=suspect-3
                
            if 'DOCTYPE html' in php_code:
                rule=rule+'DOCTYPE html,'
                suspect=suspect-2
            
            if self.check_for_variable_functionsA(php_code):
                suspect=suspect+2
                rule=rule+' check_for_variable_functionsA,'
                
            if self.check_for_variable_functionsB(php_code):
                suspect=suspect+1
                rule=rule+' check_for_variable_functionsB,'
        
        #self.syslogcc("aaaaa223")
        
        shell_insert={'filename':filename,"suspect":suspect,"rule":rule}
        #self.syslogcc(shell_insert)
        
        if suspect>=8:
            shell_insert={'filename':filename,"suspect":suspect,"rule":rule}
            #self.syslogcc(shell_insert)
            return 'Intelligence engine01'
        else:
            return ''
        return ''
        
        
        
        
    def check_for_variable_functionsA(self,php_code):
        patterns =[
           # r"\b\$?\w+\s*\(\s*(.*?)\s*\)",# 查找所有匹配项
            r"\$\w+\s*\(\s*\$\_\w+\['\w+'\]\s*\)\s*;",
             ]
        for pattern in patterns:  
            matches = re.findall(pattern, php_code)
            for match in matches:
                return True
            return False
            
    def check_for_variable_functionsB(self,php_code):
        patterns =[
           # r"\b\$?\w+\s*\(\s*(.*?)\s*\)",# 查找所有匹配项
            r'\$_(POST|GET|SESSION|REQUEST)|php://input',
             ]
        for pattern in patterns:  
            matches = re.findall(pattern, php_code)
            for match in matches:
                return True
            return False
            
    '''    
    @name 判断php脚本是否包含敏感字
    @param filename 文件名称
    @return bool 
    '''   
    def check_string_in_list(self,filename, list_to_search):
      string_to_check=public.ReadFile(filename)
      for item in list_to_search:
         if item in string_to_check:
            return True
         else:
            return False
   
   
    #判断是否存在人看不出的加密内容
    def contains_complex_strings(self,content):  
        # 正则表达式匹配由大小写字母、数字、加号、斜杠等组成的字符串  
        # 注意：这只是一个示例，可能需要根据实际情况进行调整  
        pattern = r'[A-Za-z0-9+/=]+'  
        matches = re.findall(pattern, content)  
        # 如果找到匹配项且匹配项长度足够长（例如，至少20个字符）  
        # 则认为包含“不可识别内容”  
        for match in matches:  
            if len(match) >= 80:  # 根据需要调整这个阈值  
             return True  # 返回True和匹配的字符串  
        return False
   
   
   
   
   
   
    '''    
    @name 判断php是否被混淆
    @param php_code php代码
    @return bool 
    '''   
    def is_php_code_obfuscated(self,filename):
        # 读取PHP文件内容  
        php_code=public.ReadFile(filename)
            # 定义一些常见的Webshell特征  
            # 注意：这些特征可能需要根据实际情况进行更新或扩展  
        patterns = [  
                r'\$_(GET|POST|REQUEST)\[.*\]\s*=\s*shell_exec',  # 执行shell命令  
                r'\$_(GET|POST|REQUEST)\[.*\]\s*=\s*system',  # 执行系统命令  
                r'\$_(GET|POST|REQUEST)\[.*\]\s*=\s*eval',  # 执行PHP代码  
                r'\b\$?\w+\s*\(\s*(.*?)\s*\)',#检查变量函数
                r'\b(base64_decode|gzuncompress|gzdecode|str_rot13)\b',# 检查是否存在编码或解码函数
                r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',# 检查是否存在字符串加密或混淆
                r'\b(eval|call_user_func[_array])\b',#检查是否存在复杂的嵌套结构
                # 添加更多特征...  
                ]  
                # 使用正则表达式检查每个特征  
        for pattern in patterns:  
            if re.search(pattern, php_code):  
                return True  # 找到Webshell特征  
        return False  # 未找到Webshell特征  
        
        
    '''
    @name 加入白名单
    @param input_string php代码
    ''' 
    def add_whitelist(self,filename): 
         md5_hash = self.read_file_md5(filename)
        # whitelist=self.ReadFile(self.__whitelist)
         with open(self.__whitelist, 'r', encoding='utf-8') as file:
            content = file.read()
         if md5_hash not in content:
             if os.path.exists(self.__whitelist):
               public.WriteFile(self.__whitelist,md5_hash+"\n","a+")
               return True
             else:
               public.WriteFile(self.__whitelist,md5_hash+"\n")
               return True
         return False
    
    
    '''
    @name 上传文件入口
    @param filename 文件路径
    @return bool 
    '''
    def upload_file_url2(self, filename,url):
        try:
            if os.path.exists(filename):
                ret=self.webshellchop(filename,url)
                if  ret:
                    return True
                return False
            else:
                return False
        except:
            return False
            
    def syslogcc(self,shell_insert):
        if os.path.exists(self.__shella):
            public.WriteFile(self.__shella,json.dumps(shell_insert)+"\n","a+")
        else:
            public.WriteFile(self.__shella,json.dumps(shell_insert)+"\n")
    
    '''
    @name 获取云端URL地址
    @return URL 
    '''
    def get_check_url(self):
        try:
            ret=requests.get('http://www.bt.cn/checkWebShell.php').json()
            if ret['status']:
                return ret['url']
            return False
        except:
            return False

    '''
    @name 上传文件
    @param data 文件路径集合
    @return 返回webshell 路径
    '''
    def upload_shell(self, data):
        if len(data) == 0: return []
        return_data = []
        url=self.get_check_url()
        if not url: return []
        count=0
        for i in data:
            count+=1
            if self.upload_file_url2(i,url):
                return_data.append(i)
            schedule=("%.2f" % (float(count)/float(self.__count)*100))
            public.WriteFile(self.__size,str(schedule))
        return return_data

    '''
    @name 获取当前目录下所有PHP文件
    '''
    def getdir_list(self, path_data):
        if os.path.exists(str(path_data)):
            return self.get_dir(path_data)
        else:
            return False

    '''
    @name 扫描webshell入口函数
    @param path 需要扫描的路径
    @return  webshell 路径集合
    '''
    def san_dir(self, path):
        self.__count=0
        #self.hmscan(path) 
        #河马查杀
        file = self.getdir_list(path)
        if not file:
            return []
        ##进度条
        print(file)
        self.__count=len(file)
        return_data = self.upload_shell(file)
        #写结果

        return return_data


#河马查杀
    def hmscan(self, path):
        ress=public.ExecShell("/www/server/panel/plugin/webshell_check/hm scan "+path+"/")
        #self.syslogcc("河马扫描")
        #self.syslogcc(path)
        text=public.ReadFile("/www/server/panel/plugin/webshell_check/result.csv")
        # 将文本按行分割  
        lines = text.strip().split('\n')  
        # 跳过标题行，只处理包含路径的行  
        php_paths = [line.split(',')[-1].strip() for line in lines[1:] if ',' in line]  
        # 输出结果  
        for path in php_paths:  
             self.syslogcc(path)
        return true


    # 返回站点
    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    def return_python(self):
        if os.path.exists('/www/server/panel/pyenv/bin/python'):return '/www/server/panel/pyenv/bin/python'
        if os.path.exists('/usr/bin/python'):return '/usr/bin/python'
        if os.path.exists('/usr/bin/python3'):return '/usr/bin/python3'
        return 'python'

    def san_path(self,get):
        if os.path.exists(self.__size):
            os.remove(self.__size)
        if os.path.exists(self.__shell):
            os.remove(self.__shell)
        if not  'path' in get:return public.returnMsg(False, "目录不存在")
        if  not os.path.exists(get.path):return public.returnMsg(False, "目录不存在")
        file_count = self.getdir_list(get.path)
        print(file_count)
        if not  file_count or len(file_count)==0:return public.returnMsg(False, "当前目录下没有PHP文件")
        #检查当前是否存在有运行的查杀进程
        webshell_count=public.ExecShell("ps -aux |grep webshell_check_main.py |wc -l")
        try:
            count=int(webshell_count[0].strip())
            if count>2:
                pid = public.ExecShell("ps -aux | grep webshell_check_main.py | grep -v grep | awk '{print $2}'")
                public.ExecShell("kill -9 {}".format(pid[0].strip()))
                # return public.returnMsg(False, "当前存在木马查杀进程。不支持同时运行多个查杀进程")
        except:
            return public.returnMsg(False, "启动扫描进程失败,请检查是否存在查杀进程")
        shell="%s /www/server/panel/plugin/webshell_check/webshell_check_main.py %s &"%(self.return_python(),get.path.strip())
        public.ExecShell(shell)
        return public.returnMsg(True, "已经启动扫描进程")

    #获取进度
    def get_san(self,get):
        if not os.path.exists(self.__size):return 0
        data3=public.ReadFile(self.__size)
        if isinstance(data3,str):
            data3=data3.strip()
            try:
                data=int(float(data3))
            except:
                data=0
            return data
        return 0

    #读取扫描后的文件
    def get_shell(self,get):
        time.sleep(1)
        ret=[]
        count=1
        ret.append(["序号", "md5", "路径","特征"])
        if not os.path.exists("/www/server/panel/plugin/webshell_check/shell.txt"):return []
        f = open("/www/server/panel/plugin/webshell_check/shell.txt",'r')
        for i in f:
            try:
                i=i.strip()
                i=json.loads(i)
                ret.append(["%s"%count,"%s"%i['md5'],i['filename'],i['file_type']])
                count+=1
            except:
                continue
        return ret


    #提交误报
    def send_baota(self,get):
        self.add_whitelist(get.filename)
        return public.returnMsg(True, "提交误报完成"+get.filename)

    def remove_file(self,get):
        import files
        data=files.files()
        get.path=get.filename
        return data.DeleteFile(get)
        
    def shell_update(self,get):
        public.ExecShell("/www/server/panel/plugin/webshell_check/hm update")
        return public.returnMsg(True, '更新成功!')
        
    #创建定时任务计划，进行安全扫描 
    def Scheduledplan(self,get):
        public.ExecShell("/www/server/panel/plugin/webshell_check/hm update")
        return public.returnMsg(True, '更新成功!')
            
        
if __name__ == "__main__":
    data=webshell_check_main()
    path = sys.argv[1]
    file = data.getdir_list(path)
    print(file)
    data.san_dir(path)
