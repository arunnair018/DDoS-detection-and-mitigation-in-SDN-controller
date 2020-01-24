import math
from pox.core import core
log = core.getLogger()
import time
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

class associate(object):
	s=time.time()
	pcount=0
	count=0
	sid=[]
	mac=[]
	sip=[]
	dip=[]
	packets=[]
	dict0={}
	dict1={}
	ddict=[]
	switches={}

	def collect(self,event):
		self.pcount+=1
		print self.pcount,' packet'
		dpid = event.connection.dpid
		inport = event.port
		if time.time()-self.s<0.1:
			self.count += 1
			self.packets.append(event)
			self.sid.append(dpid)
			self.ddict=[]
			if self.count == 50:
				print '+++++\n+++++'
				for e in self.packets:
					self.switches[e.connection.dpid] = e
				print self.switches
				for i,j in enumerate(self.packets):
					packet=j.parsed
					self.mac.append(packet.src)
					self.sip.append(packet.next.srcip)
					self.dip.append(packet.next.dstip)
				self.ddict.append(self.check_mac(self.mac,self.sip,self.dip,event))
				self.ddict.append(self.check_src(self.mac,self.sip,self.dip,event))
				self.count = 0
				self.packets=[]
				self.sid=[]
				self.mac = []
				self.sip = []
				self.dict0={}
				self.dict1={}
				self.switches={}
				return self.ddict
		else:
			self.count = 0
			self.packets=[]
			self.sid=[]
			self.mac = []
			self.sip = []
			self.dict0={}
			self.dict1={}
			self.ddict=[]
			self.switches={}
		self.s=time.time()

	def prevent(self,mac,event):
		for i in mac:
			print 'deleteing old entries...'
			msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
			msg.match.dl_src = EthAddr(i)
			event.connection.send(msg)
			print str(event.parsed.src)+'installing for mac address '+str(i)+' in switch '+ str(event.connection.dpid)
			match = of.ofp_match(dl_src = EthAddr(i))
			msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
								  idle_timeout=300,
								  hard_timeout=600,
								  buffer_id=event.ofp.buffer_id,
								  match=match)
			event.connection.send(msg.pack())

	def check_mac(self,mac,src,dst,event):
		macdup = list(dict.fromkeys(mac))		
		srcdup = list(dict.fromkeys(src))
		
		####check src spoofing
		for m in macdup:
			self.dict0[m] = len(list(dict.fromkeys([src[i] for i, x in enumerate(mac) if x == m])))
		if all(x>1 for x in self.dict0.values()):
			print '\n***********DDoS attack (source level)********** \n'
			for event in self.switches.values():
				self.prevent(self.dict0.keys(),event)
		else:
			print '\nNo Forging (source level)\n'


		####check dst spoofing
	def check_src(self,mac,src,dst,event):
		macdup = list(dict.fromkeys(mac))		
		srcdup = list(dict.fromkeys(src))
		for ip in srcdup:
			self.dict1[ip] = len(list(dict.fromkeys([dst[i] for i, x in enumerate(src) if x == ip])))
		print self.dict1
		if all(x>10 for x in self.dict1.values()):
			print '\n***********DDoS attack (destination level)********** \n'
			d=[]
			for ip in self.dict1.keys():
				d += list(dict.fromkeys([mac[i] for i, x in enumerate(src) if x == ip]))
			for event in self.switches.values():
				self.prevent(d,event)
		else:
			print '\nNo Forging (destination level)\n'
