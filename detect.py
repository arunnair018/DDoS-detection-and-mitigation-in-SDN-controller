import math
import time
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class associate():
	#pcount=0
	s=time.time()
	pcount=0
	count=0
	event_list=[]
	timer_list=[]

	def collect(self,event):
		self.count+=1
		self.pcount+=1;print(self.pcount)
		self.event_list.append(event)
		self.timer_list.append(time.time()-self.s)
		if self.count==50:
			l=[x for x in self.timer_list if x < 0.1]
			#print(l,'\t',len(l))
			if len(l)>12:
				self.detect(self.event_list)
			self.reset()
		self.s=time.time()

	def detect(self,event):
		mac=[e.parsed.src for e in event]
		src=[e.parsed.next.srcip for e in event]
		dst=[e.parsed.next.dstip for e in event]
		mac_dic={}
		for m in mac:
			mac_dic[m] = len(list(dict.fromkeys([src[i] for i, x in enumerate(mac) if x == m])))
		prev_event = [event[mac.index(i)] for i in [mac_dic.keys()[mac_dic.values().index(x)] for x in mac_dic.values() if x>1]]
		if prev_event:
				print('#################### DDOS DETECTED ( SOURCE ) #########################')
				self.prevent(prev_event)
		else:
			src_dic={}
			for m in src:
				src_dic[m] = len(list(dict.fromkeys([dst[i] for i, x in enumerate(src) if x == m])))
			prev_event = [event[src.index(i)] for i in [src_dic.keys()[src_dic.values().index(x)] for x in src_dic.values() if x>10]]
			if prev_event:
				print('#################### DDOS DETECTED ( DESTINATION ) #########################')
				self.prevent(prev_event)

	def prevent(self,event):
		for i in event:
			print('deeting old entries...')
			msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
			msg.match.dl_src = EthAddr(i.parsed.src)
			i.connection.send(msg)
			print 'installing flow entry for ',i.parsed.src,' in switch ',i.connection.dpid 
			match = of.ofp_match(dl_src = EthAddr(i.parsed.src))
			msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
								  idle_timeout=300,
								  hard_timeout=600,
								  buffer_id=i.ofp.buffer_id,
								  match=match)
			i.connection.send(msg.pack())


	def reset(self):
		self.count=0
		self.timer_list=[]
		self.event_list=[]
