from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import *
import getopt
import sys
class MyBrowser(QWebView):
    def __init__(self,father=None):
        super(MyBrowser,self).__init__(father)
        self.page().setLinkDelegationPolicy(QWebPage.DelegateExternalLinks)
        self.connect(self, SIGNAL("linkClicked(QUrl)"),self.onLinkClicked)
        
    def onLinkClicked(self,url):
        self.load(url)
class MonsterBrowser():
    def usage(self):
        print """
    Usage: python MonsterBrowser.py [options] url
    
    Options:
        -c  --cookie <Cookie>        set cookie
        -u --useragent <UserAgent>   set useragent
         
        """
    
    def parseArguments(self,argv):
        try:
            opts, args = getopt.getopt(argv, "c:u:", ["cookie=", "useragent="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)    
        
        url = args[0]
        cookie = None
        useragent = None
        for opt, args in opts:    
                if opt in ("-c", "--cookie"):
                    cookie = args
                    
                if opt in ("-u", "--useragent"):
                    useragent = args
                        
        if not url:
            self.usage()
            sys.exit(2)
        
        print cookie,useragent,url
        self.launch(cookie, useragent , url)
         
    def launch(self, rawcookie, useragent, host):
        cookies = []
        domain = host.split(".")[-2:]
        if domain[0] == "com":
            domain = ".".join(host.split(".")[-3:])
        else:
            domain = ".".join(host.split(".")[-2:])

        #adding cookies to cookiejar
        for cookie in rawcookie.split("; "):
            qnc = QNetworkCookie()
            qnc.setDomain("."+domain)
            key = cookie.split("=")[0]
            value = "=".join( cookie.split("=")[1:] )
            qnc.setName(key)
            qnc.setValue(value)
            cookies.append(qnc)
        self.open_web(domain, cookies,useragent)
        return
    def open_web(self, host,cookies,useragent):
        app = QApplication(sys.argv)
        wind = QMainWindow()
        view = QWebView()
        nam = QNetworkAccessManager()
        view.page().setNetworkAccessManager(nam)

        print " [!]  Spawning web view of " + host
        ncj = QNetworkCookieJar()
        ncj.setAllCookies(cookies)
        nam.setCookieJar(ncj)

        qnr = QNetworkRequest(QUrl("http://"+host))
        qnr.setRawHeader("User-Agent",useragent)

        view.load(qnr)
        wind.setCentralWidget(view)
        wind.show()  
        app.exec_()
if __name__ == "__main__":
    browser = MonsterBrowser()
    browser.parseArguments(sys.argv[1:])