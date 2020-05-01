#!/usr/bin/python3
from dnslib import *
from dnslib.server import *
import dns.rdatatype
import logging
import sys
import random

logger = logging.getLogger('DNS')
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)

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
        self.ports  = {}
        self.rrs    = {}
        self.recurse = recurse
        self._get_data()
    def __init_entry(self):
        return {'A': [], 'CNAME': None, 'SRV': [], 'TXT': [],
                'MX': [], 'PTR': None}
    def _get_data(self):
        if not self.ctrl.ping() == 'OK':    logger.error('no docker connection')
        self.data   = {}
        self.ports  = {}
        self.rrs    = {}
        for container in self.ctrl.containers():
            imgid, imgname = container['ImageID'], container['Image'].split(':', 1)[0].split('/')[-1]
            rr = self.rrs.get(imgid, {'name': imgname, 'hosts': []})
            if len(container['NetworkSettings']['Networks']) > 1:
                networks = list(filter(lambda x: x != 'DNS', \
                                container['NetworkSettings']['Networks']))
            else:
                networks = container['NetworkSettings']['Networks']
            for network in map(lambda x: container['NetworkSettings']['Networks'][x], networks):
                ip = network['IPAddress']
                rr['hosts'].append(A(ip))
                for name in container['Names']: 
                    name = name[1:] # strip docker name starts "/xxxx" 
                    name = name.replace('/', '_') # make docker-link names DNS compatible
                    entry = self.data.get(name, self.__init_entry())
                    entry['A'].append(A(ip))
                    for port in container['Ports']:
                        num = port['PrivatePort']
                        proto = port['Type'].lower()
                        if self.domain != None: target = '%s%s.' % (name, self.domain)
                        else:                   target = '%s.' % name
                        entry['SRV'].append(SRV(port=int(num), target='_%s.%s' % (proto, target)))
                        pp = self.ports.get(int(num), {'tcp':[], 'udp':[]})
                        pp[proto].append(SRV(port=int(num), target='_%s.%s' % (proto, target)))
                        self.ports[int(num)] = pp
                    self.data[name] = entry
            self.rrs[imgid] = rr
        for rr in self.rrs:
            name = self.rrs[rr]['name']
            hosts= self.rrs[rr]['hosts']
            entry   = self.data.get(name, self.__init_entry())
            entry['A'] = hosts 
            self.data[name] = entry
    def _qtype(self, rsp):
        return dns.rdatatype.from_text(rsp)
    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname
        lname = str(qname)[:-1]
        rt  = dns.rdatatype.to_text(request.q.qtype)
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
            try:
                service = lname.split('.')  
                port = int(service[0])
                proto = service[1][1:]
                logger.debug('fetching records for service %s proto %s' % (port, proto))
                rsp = self.ports.get(port, {}).get(proto)
                if rsp:
                    logger.debug('records to return %s' % rsp)
                    qt = self._qtype('SRV')
                    for h in rsp:
                        reply.add_answer(RR(qname,qt,ttl=self.ttl,
                                     rdata=h))
                    return reply
                reply.header.rcode = RCODE.NXDOMAIN
                return reply
            except Exception as e:
                logger.error('Problem returning Service records %s' % str(e))
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
    import docker

    DOMAIN  = os.environ.get('DOMAIN', None)
    RECURSE = os.environ.get('DNS', False)
    PORT    = int(os.environ.get('PORT', 53))
    ADDR    = os.environ.get('ADDRESS', '0.0.0.0')
    TTL     = os.environ.get('TTL', '60s')
    if os.environ.get('DEBUG', False):
        logger.setLevel(logging.DEBUG)
    try:
        r = DockerResolver(docker.Client().from_env(), domain=DOMAIN, ttl=TTL, recurse=RECURSE)
        l = DNSLogger(prefix=False)
        u = DNSServer(r, port=PORT, address=ADDR, logger=l, tcp=False)
        t = DNSServer(r, port=PORT, address=ADDR, logger=l, tcp=True)
        u.start_thread()
        t.start_thread()
        logger.info('started DNS service at %s:%s' % (ADDR, PORT))
        logger.info('got %s items from Docker service' % len(r.data))
        logger.info('found %s different services' % len(r.ports))
        logger.info('#' * 80)
        c = 0
        while any([u.isAlive(), t.isAlive()]):
            sleep(1)
            if c >= 10:
                r._get_data()
                c = 0
            else:
                c += 1
    except Exception as e:
        logger.error(str(e))
        while u.isAlive():
            u.stop()
        while t.isAlive():
            t.stop()
