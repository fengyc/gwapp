Architecture of gwapp
=====================

What is gwapp?
--------------

Gwapp is a proxy app written in python. The plan is to support multiple types of
protocols, authentication mechanisms, ACLs etc.

And gwapp will also provide a simple web based dashboard.

Architecture
------------

A proxy relay datagram packages between clients and remote servers ::

    Client <----> Proxy <----> Remote

Generally, proxy is configurable inside the network setting of web browsers and
operation systems.


The key components and the relations between like ::



