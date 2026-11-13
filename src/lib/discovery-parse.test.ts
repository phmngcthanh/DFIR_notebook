import { describe, expect, it } from 'vitest';
import { detectDiscoveryFormat, parseDiscovery, toMac } from './discovery-parse';

const WINDOWS_ARP = `
Interface: 192.168.1.5 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.40          aa-bb-cc-dd-ee-02     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 10.0.0.5 --- 0x9
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
`;

const LINUX_ARP = `
? (10.0.0.1) at aa:bb:cc:dd:ee:01 [ether] on eth0
gateway.corp.local (10.0.0.2) at aa:bb:cc:dd:ee:02 [ether] on eth0
? (10.0.0.9) at <incomplete> on eth0
`;

const MAC_ARP = '? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n';

const IP_NEIGH = `
10.0.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
10.0.0.7 dev eth0  FAILED
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router STALE
`;

const CISCO_ARP = `
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.1.1.1                -   aabb.ccdd.ee01  ARPA   Vlan10
Internet  10.1.1.20               3   aabb.ccdd.ee14  ARPA   Vlan10
`;

const IPCONFIG = `
Windows IP Configuration

   Host Name . . . . . . . . . . . . : WS-FIN-12
   Primary Dns Suffix  . . . . . . . : corp.local
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : corp.local
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-12
   DHCP Enabled. . . . . . . . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::1c2d:3e4f:5a6b:7c8d%12(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.20.1.44(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : fe80::1%12
                                       10.20.1.1
   DHCP Server . . . . . . . . . . . : 10.20.1.2
   DNS Servers . . . . . . . . . . . : 10.20.1.3
                                       10.20.1.4

Ethernet adapter Ethernet 2:

   Media State . . . . . . . . . . . : Media disconnected
   Physical Address. . . . . . . . . : AA-BB-CC-DD-EE-99
`;

const IP_ADDR = `
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether aa:bb:cc:dd:ee:05 brd ff:ff:ff:ff:ff:ff
    inet 10.0.0.5/24 brd 10.0.0.255 scope global dynamic eth0
       valid_lft 86000sec preferred_lft 86000sec
    inet 10.0.0.55/24 scope global secondary eth0
    inet6 fe80::a8bb:ccff:fedd:ee05/64 scope link
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:ac:11:00:01 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
`;

const IFCONFIG = `
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::a8bb:ccff:fedd:ee05  prefixlen 64  scopeid 0x20<link>
        ether aa:bb:cc:dd:ee:05  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
`;

const NMAP = `
# Nmap 7.94 scan initiated Thu Nov 12 10:00:00 2026 as: nmap -sS -O -oN scan.txt 10.0.0.0/24
Nmap scan report for gateway.corp.local (10.0.0.1)
Host is up (0.00050s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open|filtered https
8443/tcp open https-alt
MAC Address: AA:BB:CC:DD:EE:01 (Ubiquiti Networks)
Device type: general purpose
Running: Linux 4.X|5.X
OS details: Linux 4.15 - 5.6

Nmap scan report for 10.0.0.40
Host is up (0.0010s latency).
All 1000 scanned ports on 10.0.0.40 are filtered
MAC Address: AA:BB:CC:DD:EE:02 (Unknown)

Nmap scan report for 10.0.0.50
Host is up.

Nmap done: 256 IP addresses (3 hosts up) scanned in 3.21 seconds
`;

const NMAP_GREPPABLE = `
# Nmap 7.94 scan initiated Thu Nov 12 10:00:00 2026 as: nmap -oG scan.gnmap 10.0.0.0/24
Host: 10.0.0.1 (gateway.corp.local)\tStatus: Up
Host: 10.0.0.1 (gateway.corp.local)\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 8080/closed/tcp//http-proxy///\tIgnored State: closed (995)
Host: 10.0.0.9 ()\tStatus: Up
`;

const ISC_LEASES = `
lease 10.0.0.50 {
  starts 4 2026/11/12 08:00:00;
  ends 4 2026/11/12 20:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:50;
  client-hostname "PC50";
}
lease 10.0.0.51 {
  starts 3 2026/11/11 08:00:00;
  binding state free;
  hardware ethernet aa:bb:cc:dd:ee:51;
}
lease 10.0.0.50 {
  starts 4 2026/11/12 12:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:50;
  client-hostname "PC50";
}
`;

describe('toMac', () => {
  it('reads every notation and rejects what is not a hardware address', () => {
    expect(toMac('aa-bb-cc-dd-ee-01')).toBe('AA:BB:CC:DD:EE:01');
    expect(toMac('0:1a:2b:3c:4d:5e')).toBe('00:1A:2B:3C:4D:5E');
    expect(toMac('aabb.ccdd.ee01')).toBe('AA:BB:CC:DD:EE:01');
    expect(toMac('<incomplete>')).toBe('');
  });
});

describe('detectDiscoveryFormat', () => {
  it.each([
    [WINDOWS_ARP, 'arp'], [LINUX_ARP, 'arp'], [MAC_ARP, 'arp'], [IP_NEIGH, 'arp'], [CISCO_ARP, 'arp'],
    [IPCONFIG, 'ipconfig'], [IP_ADDR, 'ipaddr'], [IFCONFIG, 'ipaddr'],
    [NMAP, 'nmap'], [NMAP_GREPPABLE, 'nmap'], [ISC_LEASES, 'dhcp'],
    ['1731600000 aa:bb:cc:dd:ee:60 10.0.0.60 laptop-60 01:aa:bb:cc:dd:ee:60', 'dhcp'],
  ])('recognizes %#', (text, format) => {
    expect(detectDiscoveryFormat(text)).toBe(format);
  });

  it('says nothing about prose', () => {
    expect(detectDiscoveryFormat('The client says finance owns APP01.')).toBeNull();
  });
});

describe('ARP and neighbor tables', () => {
  it('reads Windows arp -a, dropping broadcast and multicast rows and repeats across interfaces', () => {
    const { hosts } = parseDiscovery(WINDOWS_ARP);
    expect(hosts.map((host) => [host.nics[0].ip, host.nics[0].mac])).toEqual([
      ['192.168.1.1', 'AA:BB:CC:DD:EE:01'],
      ['192.168.1.40', 'AA:BB:CC:DD:EE:02'],
    ]);
  });

  it('reads Linux arp -a with names, skips incomplete entries, and drops "?" names', () => {
    const { hosts } = parseDiscovery(LINUX_ARP);
    expect(hosts.map((host) => [host.name, host.nics[0].ip, host.nics[0].mac])).toEqual([
      ['', '10.0.0.1', 'AA:BB:CC:DD:EE:01'],
      ['gateway.corp.local', '10.0.0.2', 'AA:BB:CC:DD:EE:02'],
    ]);
  });

  it('reads macOS short octets, ip neigh without failed or IPv6 entries, and Cisco dotted MACs', () => {
    expect(parseDiscovery(MAC_ARP).hosts[0].nics[0].mac).toBe('00:1A:2B:3C:4D:5E');
    expect(parseDiscovery(IP_NEIGH).hosts.map((host) => host.nics[0].ip)).toEqual(['10.0.0.1']);
    expect(parseDiscovery(CISCO_ARP).hosts.map((host) => [host.nics[0].ip, host.nics[0].mac])).toEqual([
      ['10.1.1.1', 'AA:BB:CC:DD:EE:01'],
      ['10.1.1.20', 'AA:BB:CC:DD:EE:14'],
    ]);
  });

  it('warns when one address shows up with two MAC addresses, and keeps both hosts', () => {
    const { hosts, warnings } = parseDiscovery('10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n10.0.0.5 dev eth1 lladdr aa:bb:cc:dd:ee:02 STALE\n');
    expect(hosts).toHaveLength(2);
    expect(warnings).toEqual([expect.stringContaining('10.0.0.5 appears with 2 different MAC addresses')]);
  });
});

describe('ipconfig /all', () => {
  it('reads the host and its connected adapters, and lists gateway, DHCP and DNS servers as references', () => {
    const { hosts } = parseDiscovery(IPCONFIG);
    expect(hosts[0]).toEqual({
      name: 'WS-FIN-12',
      nics: [{ name: 'Ethernet0', ip: '10.20.1.44', mac: 'AA:BB:CC:DD:EE:12' }],
      os: 'Windows',
    });
    expect(hosts.slice(1).map((host) => [host.nics[0].ip, host.reference])).toEqual([
      ['10.20.1.1', 'default gateway of WS-FIN-12'],
      ['10.20.1.2', 'DHCP server of WS-FIN-12'],
      ['10.20.1.3', 'DNS server of WS-FIN-12'],
      ['10.20.1.4', 'DNS server of WS-FIN-12'],
    ]);
  });
});

describe('ip addr and ifconfig', () => {
  it('reads every address of every real interface under the host name it was given', () => {
    const { hosts, warnings } = parseDiscovery(IP_ADDR, { hostName: 'web01' });
    expect(hosts).toEqual([{
      name: 'web01',
      nics: [
        { name: 'eth0', ip: '10.0.0.5', mac: 'AA:BB:CC:DD:EE:05' },
        { name: 'eth0:1', ip: '10.0.0.55', mac: 'AA:BB:CC:DD:EE:05' },
      ],
    }]);
    expect(warnings).toEqual(['Skipped 2 loopback or virtual interfaces (lo, docker, veth, bridges).']);
  });

  it('reads the older ifconfig layout and leaves the host unnamed when none is given', () => {
    const { hosts } = parseDiscovery(IFCONFIG);
    expect(hosts[0].name).toBe('');
    expect(hosts[0].nics).toEqual([{ name: 'eth0', ip: '10.0.0.5', mac: 'AA:BB:CC:DD:EE:05' }]);
  });
});

describe('nmap', () => {
  it('reads hosts with open ports, MAC vendor, OS and the scan time from normal output', () => {
    const { hosts } = parseDiscovery(NMAP);
    expect(hosts).toHaveLength(3);
    expect(hosts[0]).toEqual(expect.objectContaining({
      name: 'gateway.corp.local',
      vendor: 'Ubiquiti Networks',
      os: 'Linux 4.15 - 5.6',
      ports: [
        { port: 22, protocol: 'tcp', service: 'ssh' },
        { port: 80, protocol: 'tcp', service: 'http' },
        { port: 8443, protocol: 'tcp', service: 'https-alt' },
      ],
    }));
    expect(hosts[0].nics[0]).toEqual({ name: 'Primary', ip: '10.0.0.1', mac: 'AA:BB:CC:DD:EE:01' });
    expect(Date.parse(hosts[0].observedAt ?? '')).not.toBeNaN();
    // "Unknown" is not a vendor.
    expect(hosts[1].vendor).toBeUndefined();
    expect([hosts[1].name, hosts[1].ports]).toEqual(['', []]);
    expect(hosts[2].nics[0].mac).toBe('');
  });

  it('reads greppable output, merging a host\'s status and ports lines', () => {
    const { hosts } = parseDiscovery(NMAP_GREPPABLE);
    expect(hosts.map((host) => [host.name, host.nics[0].ip, host.ports?.map((port) => port.port)])).toEqual([
      ['gateway.corp.local', '10.0.0.1', [22, 80]],
      ['', '10.0.0.9', []],
    ]);
  });

  it('asks for a different output format instead of guessing at XML', () => {
    expect(() => parseDiscovery('<?xml version="1.0"?><nmaprun scanner="nmap">')).toThrow(/-oN/);
  });
});

describe('DHCP leases', () => {
  it('reads dhcpd.leases, keeping the latest lease per address and noting leases that are not active', () => {
    const { hosts } = parseDiscovery(ISC_LEASES);
    expect(hosts.map((host) => [host.name, host.nics[0].ip, host.nics[0].mac, host.observedAt, host.note])).toEqual([
      ['PC50', '10.0.0.50', 'AA:BB:CC:DD:EE:50', '2026-11-12T12:00:00.000Z', undefined],
      ['', '10.0.0.51', 'AA:BB:CC:DD:EE:51', '2026-11-11T08:00:00.000Z', 'lease free'],
    ]);
  });

  it('reads dnsmasq, netsh and PowerShell exports', () => {
    expect(parseDiscovery('1731600000 aa:bb:cc:dd:ee:60 10.0.0.60 laptop-60 01:aa:bb:cc:dd:ee:60\n1731600000 aa:bb:cc:dd:ee:61 10.0.0.61 * *\n').hosts
      .map((host) => [host.name, host.nics[0].ip])).toEqual([['laptop-60', '10.0.0.60'], ['', '10.0.0.61']]);
    expect(parseDiscovery('10.0.0.70       - 255.255.255.0 - aa-bb-cc-dd-ee-70   - 11/13/2026 8:00:00 AM  -D-  PC70.corp.local\n').hosts[0])
      .toEqual(expect.objectContaining({ name: 'PC70.corp.local', nics: [{ name: 'Primary', ip: '10.0.0.70', mac: 'AA:BB:CC:DD:EE:70' }] }));
    const csv = '"IPAddress","ScopeId","AddressState","ClientId","HostName"\n"10.0.0.80","10.0.0.0","Active","aa-bb-cc-dd-ee-80","PC80.corp.local"\n';
    expect(parseDiscovery(csv).hosts[0]).toEqual(expect.objectContaining({ name: 'PC80.corp.local', nics: [{ name: 'Primary', ip: '10.0.0.80', mac: 'AA:BB:CC:DD:EE:80' }] }));
  });
});

describe('parseDiscovery errors', () => {
  it('explains an empty paste, unrecognized text, and output with no usable host', () => {
    expect(() => parseDiscovery('   ')).toThrow('Paste the output first');
    expect(() => parseDiscovery('Finance owns APP01')).toThrow(/Choose the format/);
    expect(() => parseDiscovery('Interface: 10.0.0.5 --- 0x4\n  Internet Address      Physical Address      Type\n', { format: 'arp' })).toThrow(/No hosts with an address/);
  });
});
