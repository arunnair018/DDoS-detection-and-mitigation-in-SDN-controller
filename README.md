# DDoS-detection-and-mitigation-in-SDN-controller
### A Software-defined IoT gateway model to provide a more agile, secure, programmable gateway for IoT networks. Integrated with monitoring and mitigation methods to address the issue of DDoS attack in IoT  
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
   ```
