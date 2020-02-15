# DDoS-detection-and-mitigation-in-SDN-controller
## An algorithm to detect and mitigate DDoS attack in a SDN.  
To install mininet  
```
$ git clone git://github.com/mininet/mininet
$ cd mininet
$ mininet/util/install.sh -a
```  
To install POX controller  
```
$ git clone http://github.com/noxrepo/pox
$ cd pox
```  
To run mininet topology, run miniedit and open topology.mn file.    
For simulation of controller,
   1) Paste detect.py and l3.py in pox/pox/forwarding/
   2) Run pox controller:
   ```
   $ ./pox.py forwarding.l3
   ``
