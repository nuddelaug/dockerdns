# Private DNS service for Docker for people which cannot effort other Orchestration tools

## purpose and scope of the tool

I found it quiet annoying without an Orchestration tool, to build complex, depending Proof of Concepts. DNS names
are mandatory for some and even with _hacking_ through links in Docker, you'll sooner or later discover the Chicken-Egg 
Problem.

So for the Scope: The tool is not ment to be Production ready. Use it at your own risk. It's intend to provide a DNS view to
all your Containers on *one* Host. No High Availability or similar stuff even though one could _expose_ multiple Docker instances
through TCP, but there I would recommend you to look into proper Orchestration tools.

## todo's

right now, the tools does not listen for notifications on the docker daemon socket (didn't had time to look into that already) so it will refresh the DNS records only every 10 seconds.

## requirements

Ahhh, I didn't find my Docker Hub login and resetting the Account never brought an Email from them so, I've not uploaded an image.

* Docker 
* Docker Network for DNS (I'll explain later why)
* privileged access unfortunately otherwise you'll not get anything from the Docker daemon.

## Setup and configuration

### Docker Network for DNS

why ? yes because without a custom Network, you can't guarantee that the service(s) will have the same IP after stoping/reboot.
So create a custom Network, to make it simple we'll call it DNS and i pick a random IP Range (but it should be as big as the default bridge depending on your Container count)

```bash
docker network create --attachable -d bridge --gateway 172.22.0.1 --ip-range 172.22.0.0/16 --subnet 172.22.0.0/16 DNS
```

the reason you need an custom Network comes from Docker not letting you _reserve_ a fix IP for the service and updating your resolv.conf files over and over is annoying.

### building the image 

yes, sorry as mentioned above, I didn't find my Github ID so I'm not able to upload a container right now. 
To build the image which is based upon CentOS 8 (latest) and python3.6, checkout the repository and execute

```bash
docker build --rm -t dockerdns:latest .
```

since you build it on your own, you can also name it as you want ... 
afterwards you can run the image with some Environment Variables set to controll the behavior:

* DOMAIN = which domain is appended to container Names (Container www -> www.example.com.)
           you don't need a domain the hosts will then be available as www., jenkins. ...
* RECURSE= which makes the service response for recursive queries so that you don't need a DNS setup on your Laptop
           where a specific Domain contains the Container names.
           This is the Variable you want to forward the queries to (Infrastructure DNS, google 8.8.8.8)
* PORT   = the Port DNS queries will be accepted, default to 53 tcp/udp
* ADDR   = Address to listen on for DNS queries, but due to Networking, default is to 0.0.0.0
* TTL    = the default TTL for records to be applied, don't choose this to high if you are spawning a lot, default=60s
* DEBUG  = adds more debugging output 

so for the example, we don't go with any domain to keep logic short

```bash
docker run -d --restart always --net DNS --ip 172.22.254.1 -p 53:53 -p 53:53/udp --privileged \
           -v /var/run/docker.sock:/var/run/docker.sock \
           -e RECURSE=8.8.8.8 dockerdns:latest
``` 

now, why privileged and access to Docker daemon socket ? yes otherwise you'll not be able to retrieve the list of containers and
their configurations to be returned as DNS records.

## verify your configuration

now still without touching any of the other containers, you can retrieve DNS records and see if everything is working fine.
We assume there's a Container running providing http and a Python app providing a REST interface on 8080 

```
docker ps 

CONTAINER ID        IMAGE                                                COMMAND                  CREATED             STATUS              PORTS                                      NAMES
be8d3bda591e        dockerdns:latest                                     "/app.py"                26 minutes ago      Up 26 minutes       53/tcp, 53/udp                      
e83867918d71        docker.io/centos/python-34-centos7                   "/app.py"                13 days ago         Up 6 days           8080/tcp                                   fancy_pants_docker
bea87720b844        centos/httpd                                         "/run-httpd.sh"          3 weeks ago         Up 7 days           80/tcp                                     httpd
62b1b716985d        docker.io/centos/python-34-centos7     "/entrypoint.sh"         About a minute ago   Up About a minute   8080/tcp                                         musing_einstein
eb0665bea3c3        docker.io/centos/python-34-centos7     "/entrypoint.sh"         About a minute ago   Up About a minute   8080/tcp                                         affectionate_jang
9c6c46a1fe70        docker.io/centos/python-34-centos7     "/entrypoint.sh"         About a minute ago   Up About a minute   8080/tcp                                         nifty_curie

```

now using your favorite DNS query tool (I'll just pick dig now) to get informations for the Containers running:

* query, what's the IP address for my httpd Container named httpd
```
dig +short @172.22.254.1 -t a httpd.
172.17.0.7
```

* query, I don't know the name of my REST API as it's scratchable and statless service scalled at need, but I know the port 8080 ?
```
dig +short @172.22.254.1 -t any 8080._tcp. 
0 0 8080 _tcp.fancy_pants_docker.
0 0 8080 _tcp.musing_einstein.
0 0 8080 _tcp.affectionate_jang.
0 0 8080 _tcp.nifty_curie.

dig +short @172.22.254.1 -t any fancy_pants_docker.
172.17.0.5
0 0 8080 _tcp.fancy_pants_docker.

```

so what ever your Container exposes on ports this will be added as SRV record to be available information 
```
dig +short @172.22.254.1 -t any 53._udp.
0 0 53 _udp.dns1.
```

* but I need to resolve public IP Addresses. That's fine we've added a RECURSE so go on
```
dig +short @172.22.254.1 -t a www.google.com.
172.217.16.196
```

* but I need to resolve internal resources. Well as long as your internal DNS handles forwarind of none local Resources, just use the IP address in the evironment RECURSE=xxx.xxx.xxx.xxx


## change the DNS resolver

if you want to change your configuration so that all containers and even build utilizies the service you'll need to update your docker daemon.json file /etc/docker/daemon.json and add the IP addresse of your Container Host not the dockerdns instance. You can utilize either a secondary IP Address or a Load balancer infront to make the service higher available.

```bash
cat /etc/docker/daemon.json
{ "dns": [ "<yourHostIP>" ] } 
```

of course if you already have other configuration options set, please just add the dns into it so that it's valid json syntax.
Unfortunately now you would have to _restart_ your docker daemon to take the changes in affect.

## but how can my Containers reach the service they are not on the same Network

yes that's now the part where you after changing the DNS setting, you've provided port 53 on your host mapped to the dockerdns instance. It's not possible to go within the same Network neither does docker plain grant you to forward from the interfae docker0 to docker0.

If you named the Network DNS the Daemon will not return a Record for any resource queried as it's ment to be a DNS query and not other traffic carrying network.


