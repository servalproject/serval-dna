Integration of servald with OpenBTS
===================================

The quick start guide that came with the RangeNetworks 5150 unit provided sufficient information to turn it on and configure it. 
While we were setting up basic configuration for the unit, we unplugged the radio hardware to ensure that it would not cause any unexpected transmissions.
However the documentation was slightly incorrect. The unit booted with IP address 192.168.0.22, instead of 192.168.0.21 from the quick start guide.

Note;
The simplest methods for modifying OpenBTS config are via the CLI command line or web interface. 
However if the configuration is invalid this may cause OpenBTS to fail to start. In which case you will have no choice but to edit the config directly in the sqlite database /etc/OpenBTS/OpenBTS.db.

To reduce the risk of interference for bench testing, set the attenuation to the highest value that still allows phones to discover and connect to the network
eg
```
> ./CLI
> OpenBTS> power 60 60
> [Ctrl-D, A]
```

Follow the quick start quide to provision two handsets for testing.

Get a copy of the source code for serval-dna
```
> git clone git://github.com/servalproject/serval-dna.git
> cd serval-dna
```

The OpenBTS unit is running Ubuntu 10.4, the compilation of servald should be the same as any other supported platform. Refer to [../INSTALL.md](../INSTALL.md) for more information.
```
serval-dna> autoreconf -f -i
serval-dna> ./configure
serval-dna> make
```

Install servald
```
> sudo mkdir /var/serval-node
```

Configure servald to start when the server boots. This can be achieved by adding a "servald start" command to /etc/rc.local.

To build our channel driver, we need some of the build artefacts produced by compiling asterisk from scratch.
Download the source for asterisk 1.8 LTS, follow instructions to compile it. Then install asterisk.
```
asterisk_src> sudo make install
```

Build the serval / asterisk channel driver
```
> git clone git://github.com/servalproject/app_servaldna.git
> cd app_servaldna
```

Edit the Makefile to set the paths to servald and asterisk source then build it.
```
app_servaldna> make
```

Deploy the vomp channel driver to the asterisk modules directory
```
app_servaldna> sudo cp app_servaldna.so /usr/lib/asterisk/modules/app_servaldna.so
```

Replace asterisk sample configuration with a simpler set of configuration that we've prepared earlier
```
app_servaldna> sudo rm -r /etc/asterisk/
app_servaldna> sudo cp conf_adv/asterisk/* /etc/asterisk/
```

You will need to edit /etc/asterisk/extensions.conf to include the correct paths for servald and servaldnaagi.py

Copy sample servald configuration to resolve openbts phone numbers, you may need to correct the path to num2sip.py
```
app_servaldna> sudo cp conf_adv/serval.conf /var/serval-node/
```

Add an identity to servald. If you don't create one manually, and identity will be created when you first start the server. 
Take note of this public key for later use while verifying that everything is working correctly.
```
> servald keyring add
sid:[SID of BTS unit]
did:[default phone number]
```

You should configure a meaningful name to display to other serval devices. The phone number you specify here will be dialed when a user attempts to call this instance of servald from their list of peers.
You may wish to configure this to dial an echo test extension in asterisk.
```
> servald set did [SID of BTS unit] [phone number] [name] 
```

Make sure all services are re-started


Functional testing
------------------

OpenBTS phone to local asterisk test number
The supplied configuration includes extension 10411 for an echo test, call this number from one of the provisioned phones.

OpenBTS phone to another local OpenBTS phone

Remote number resolution of OpenBTS numbers
On another machine running servald with a network path to the OpenBTS unit
```
> servald dna lookup [number]
sid://[SID of BTS unit]/[ext]:[ext]:
```

Remote call to local asterisk test number
Set the phone number of a servald identity to an asterisk extension configured with an echo test. Then call this device from a serval phone using the peer list.

OpenBTS call to remote serval phone

Remote phone call to OpenBTS phones

