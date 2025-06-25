# coding:utf-8
import socket



def check(ip, port, timeout=15):
    b = "149\x00ll|'|'|SGFjS2VkXzc2MTNBMTJG|'|'|SERVERPC|'|'|ser|'|'|17-05-11|'|'||'|'|Win 8.1 ProSP0 x86|'|'|No|'|'|0.7d|'|'|..|'|'|UHJvZ3JhbSBNYW5hZ2VyAA==|'|'|[endof]"
    d = "178\x00ll|'|'|SGFjS2VkXzdFODVDNzM0|'|'|ADEL-PC|'|'|adel|'|'|17-05-12|'|'||'|'|Win 7 Ultimate SP1 x86|'|'|No|'|'|0.7d|'|'|..|'|'|QzpcV2luZG93c1xzeXN0ZW0zMlxjbWQuZXhlIC0gcHl0aG9uAA==|'|'|108\x00inf|'|'|SGFjS2VkDQoxMjcuMC4wLjE6NTU1Mg0KRG93bmxvYWRzDQpTZXJ2ZXIuZXhlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ==60\x00act|'|'|QzpcV2luZG93c1xzeXN0ZW0zMlxjbWQuZXhlIC0gcHl0aG9uAA==[endof]"
    f = "149\x00ll|'|'|SGFjS2VkXzc2MTNBMTJG|'|'|JOJO|'|'|jojo|'|'|17-05-11|'|'||'|'|Win 8.1 ProSP0 x86|'|'|No|'|'|0.7d|'|'|..|'|'|UHJvZ3JhbSBNYW5hZ2VyAA==|'|'|[endof]"
    g = "lv|'|'|TndfQzQyNjRFQkI=|'|'|VICTIM|'|'|Examiner|'|'|2013-06-21|'|'|USA|'|'|Win XP ProfessionalSP2x86|'|'|No|'|'|0.5.0E|'|'|..|'|'|Y3B0YnRfUHJvY2Vzc19SZWdpc3RyeV9GaWxlX0luZm8ubG9nIC0gTm90ZXBhZA==|'|'|[endof]"
    h = "act|'|'|Y3B0YnRfUHJvY2Vzc19SZWdpc3RyeV9GaWxlX0luZm8ubG9nIC0gTm90ZXBhZA== [endof]"

    try:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip , port))
        s.send(g)
        receive = (s.recv(100000))
        s.close()
        if receive.startswith('CAP') or receive.endswith('[endof]'):
            print "find njRAT!"
            return 'ip:%s,port:%d,receive:%s,type:%s'%(ip,port,receive,'njRAT')
    except Exception, e:
        print 'timeout'
        s.close()
    return None

if __name__ == '__main__':
    check('54.246.209.20',80)
    check('54.154.81.16', 80)
    check('94.31.29.128', 443)
    check('52.48.96.210', 80)