#!/usr/bin/python3
from dnslib import *
from dnslib.server import *
import dns.rdatatype
import logging
import sys
import random
from threading import Thread
import json
import docker
from IPy import IP

logger = logging.getLogger('DNS')
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)

class DockerBackend(Thread):
    def __init__(self, ctrl=None, handler=None):
        Thread.__init__(self)
        self.ctrl           = ctrl
        self._handler       = handler
        self._containers    = {}
    def ping(self):
        try:
            rsp = self.ctrl.ping()
            if not rsp == 'OK':
                logger.error('no docker connection')
            return True
        except Exception as e:
            logger.error('docker: %s' % str(e))
        return False
    def containers(self):
        if self.ping():
            if self._containers == {}:
                for c in self.ctrl.containers():
                    self._containers[c.get('Id')] = c
            return list(self._containers.values())
    def _remove_(self, event):
        if self._containers.get(event.get('id'), False):
            logger.debug('removing container: %s' % event.get('id'))
            logger.debug(self._containers[event.get('id')])
            try:    self._handler.update_data(self._containers[event.get('id')], remove=True)
            except Exception as e:  
                logger.error('handler raise Exception removing container %s' % str(e))
                del self._containers[event.get('id')]
                return False
            del self._containers[event.get('id')]
        else:
            logger.debug('id %s not found' % event.get('id'))
        return True
    def _add_(self, event):
        if not self._containers.get(event.get('id'), False):
            logger.debug('adding container: %s' % event.get('id'))
            self._containers[event.get('id')] = self.ctrl.containers(filters={'id': event.get('id')})[0]
            logger.debug(self._containers[event.get('id')])
            try:    self._handler.update_data(self._containers[event.get('id')])
            except Exception as e:  
                logger.error('hanlder raise Exception adding container %s' % str(e))
                return False
        else:
            logger.debug('id %s not found' % event.get('id'))
        return True
    def events(self):
        for event in self.ctrl.events():
            try:    event = json.loads(event)
            except Exception as e:
                logger.error('couldnt parse Docker event %s' % str(e))
                continue
            logger.debug('received Docker event type %s state %s' % (event.get('Type'), event.get('status')))
            if all([event.get('Type') == 'container',
                    event.get('status') in ('kill', 'destroy', 'stop', 'die')]):
                self._delete_(event)
                continue
            if all([event.get('Type') == 'container',
                    event.get('status') in ('start',)]):
                self._add_(event)
                continue
            if all([event.get('Type') == 'container',
                    event.get('status') in ('rename',)]):
                logger.debug('trying to rename %s' % event.get('id'))
                self._remove_(event)
                self._add_(event)
                continue
    def run(self):
        try:
            while self.isAlive():
                self.events()
        except: self.stop()
    def stop(self):
        try:    self._Thread__stop()
        except: pass
    
class DockerResolver(BaseResolver):
    def __init__(self,docker_ctrl,domain=None,ttl='60s',recurse=False):
        self.ctrl   = docker_ctrl
        self.ttl    = parse_time(ttl)
        if all([domain != None, str(domain).endswith('.')]):
            domain = '.' + domain[:-1]
        elif domain != None:
            domain = '.' + domain
        else:   pass
        self.domain = domain
        self.data   = {}
        self.recurse = recurse
        self.whoami = os.environ.get('HOSTNAME')
        self.iam    = None
    def notify_backend(self):
        if isinstance(self.ctrl, DockerBackend):
            self.ctrl._handler = self
        for container in self.ctrl.containers():
            self.update_data(container)
        # start off Docker polling in the background
        self.ctrl.start()
    def __init_entry(self):
        return {'A': [], 'CNAME': None, 'SRV': [], 'TXT': [],
                'MX': [], 'PTR': None , 'AAAA': [] }
    def update_data(self, container, remove=False):
        if remove == False:
            # find myself
            if container['Id'].startswith(self.whoami):
                self.iam    = container['Names'][0][1:].replace('/','') 
            imgid, imgname = container['ImageID'], container['Image'].split(':', 1)[0].split('/')[-1]
            # see if we run multiple euqal images to make a Round Robin
            rr  = self.data.get(imgname, self.__init_entry())
            if len(container['NetworkSettings']['Networks']) > 1:
                networks = list(filter(lambda x: x != 'DNS', \
                                container['NetworkSettings']['Networks']))
            else:
                networks = container['NetworkSettings']['Networks']
            # create an A Record for all Names in all LAN's except named DNS
            for network in map(lambda x: container['NetworkSettings']['Networks'][x], networks):
                ip = network['IPAddress']
                ipv6 = network['GlobalIPv6Address']
                if ipv6 != '':  rr['AAAA'].append(ipv6)
                rr['A'].append(A(ip))
                # do all names to IP and links to aliases
                for name in container['Names']:
                    name    = name[1:].replace('/', '_')   # strip docker syntax and make names DNS compatible
                    # if we are adding ourself, add SOA and NS records as well
                    if name == self.iam:
                        if self.domain == None: domain  = '.'
                        else:                   domain  = self.domain[1:]
                        auth        = self.data.get(domain, self.__init_entry())
                        auth['NS']  = [ NS(name) ]
                        auth['SOA'] = [ SOA(domain, name, times=(20200502, 86400, 7200, 600, 10)) ]
                        self.data[ domain ] = auth
                    entry   = self.data.get(name, self.__init_entry())
                    entry['A'].append(A(ip))
                    # make a PTR for the A record just added
                    rname   = IP(ip).reverseName()[:-1]
                    reverse = self.data.get(rname, { 'PTR': None })
                    if self.domain != None: reverse['PTR'] = PTR(name+self.domain+'.')
                    else:                   reverse['PTR'] = PTR(name)
                    self.data[rname] = reverse
                    # add service records for each Exposed port
                    for port, proto in map(lambda x: (int(x['PrivatePort']), x['Type'].lower()), \
                                            container['Ports']):
                        # see if we need to append a domain name
                        if self.domain != None: target = '%s%s.' % (name, self.domain)
                        else:                   target = '%s.' % name
                        # append a SRV record to the Host and a A record to the Service
                        entry['SRV'].append(SRV(port=port, target=target))
                        srvname = '%s._%s' % (port, proto)
                        service = self.data.get(srvname, self.__init_entry())
                        service['SRV'].append(SRV(port=port, target=target))
                        # update the service
                        self.data[srvname] = service
                    # ToDO: add Label links
                    # update the Host
                    self.data[name] = entry
                    # update the Round Robin
                    self.data[imgname] = rr
        else:
            # fetch all names and remove records accordingly
            imgid, imgname = container['ImageID'], container['Image'].split(':', 1)[0].split('/')[-1]
            logger.debug('imgid %s imgname %s' % (imgid, imgname))
            for name in container['Names']:
                name    = name[1:].replace('/', '_')   # strip docker syntax and make names DNS compatible
                logger.debug('rolling through container keys %s' % name)
                entry   = self.data.get(name, False)
                if not entry:
                    logger.error('unable to remove name %s out of sync?' % name)
                    continue
                # first remove all Service links
                for rec in entry.get('SRV'):
                    for proto in ('tcp', 'udp'):
                        srvname = '%s._%s' % (rec.port, proto)
                        logger.debug('removing service entries when possible %s' % srvname)
                        try:    self.data.get(srvname)['SRV'].remove(rec)
                        except Exception as e: pass
                # remove any Round Robin link
                rrentry   = self.data.get(imgname, False)
                if not rrentry:
                    logger.error('unable to remove %s from RR %s out of sync?' % (name, imgname))
                    continue
                for rec in entry.get('A'):
                    logger.debug('removing Round Robin entries %s' % rec)
                    try:    rrentry['A'].remove(rec)
                    except ValueError as e:
                        logger.error('unable to remove IP %s from RR %s out of sync?' % (rec, imgname))
                    logger.debug('removing PTR records for %s' % name)
                    rname   = IP(str(rec)).reverseName()[:-1]
                    try:    del self.data[rname]
                    except: logger.debug('couldnt remove reverse %s for %s' % (rname, name))
                # remove any Label links
                # ToDo
                del self.data[name]
    def _qtype(self, rsp):
        return dns.rdatatype.from_text(rsp)
    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname
        lname = str(qname)[:-1]
        rt  = dns.rdatatype.to_text(request.q.qtype)
        # if we have a Domain set, we want to remove it for lookups
        if self.domain != None:
            logger.debug('stripping domain %s from %s' % (self.domain, lname))
            rsp = self.data.get(lname.replace(self.domain, ''), False)
            if not rsp:
                rsp = self.data.get(lname, False)
        else:
            rsp = self.data.get(lname, False)
        if rsp:
            if rt == 'ANY': rtc = rsp.keys()
            else:           rtc = [ rt ]
            logger.debug('fetching record types: %s' % ','.join(rtc))
            for d in rtc:
                qt = self._qtype(d)
                if d in ('CNAME', 'PTR'):
                    if rsp[d] == None:  continue
                    reply.add_answer(RR(qname,qt,ttl=self.ttl,
                                       rdata=rsp[d]))
                else:
                    rsps = rsp.get(d, [])
                    random.shuffle(rsps)
                    for dd in rsps:
                        reply.add_answer(RR(qname,qt,ttl=self.ttl,
                                       rdata=dd))
            return reply
        else:
            # we shouldn't match else anymore with updating how records are stored
            # except for recursion
            if self.recurse:
                recurse = request.send(self.recurse)
                reply   = DNSRecord.parse(recurse)
                reply.header.id = request.header.id
                reply.question = request.question
                return reply
            else:
                logger.debug('Key lookup for %s: return False' % lname)
                reply.header.rcode = RCODE.NXDOMAIN
                return reply

if __name__ == '__main__':
    from time import sleep
    import os

    DOMAIN  = os.environ.get('DOMAIN', None)
    RECURSE = os.environ.get('DNS', False)
    PORT    = int(os.environ.get('PORT', 53))
    ADDR    = os.environ.get('ADDRESS', '0.0.0.0')
    TTL     = os.environ.get('TTL', '60s')
    if os.environ.get('DEBUG', False):
        logger.setLevel(logging.DEBUG)
    try:
        b = DockerBackend(docker.Client().from_env())
        r = DockerResolver(b, domain=DOMAIN, ttl=TTL, recurse=RECURSE)
        r.notify_backend() 
        l = DNSLogger(prefix=False)
        u = DNSServer(r, port=PORT, address=ADDR, logger=l, tcp=False)
        t = DNSServer(r, port=PORT, address=ADDR, logger=l, tcp=True)
        u.start_thread()
        t.start_thread()
        logger.info('started DNS service at %s:%s' % (ADDR, PORT))
        if DOMAIN != None:  logger.info('acting as Domain: %s' % DOMAIN)
        logger.info('got %s items from Docker service' % len(r.data))
        logger.info('introducing myself: %s at %s' % (r.iam, r.data.get(r.iam)['A'][0]))
        logger.info('#' * 80)
        c = 0
        while any([u.isAlive(), t.isAlive()]):
            sleep(0.1)
    except Exception as e:
        try:    b.stop()
        except: pass
        try:    u.stop()
        except: pass
        try:    t.stop()
        except: pass
        logger.error(str(e))
