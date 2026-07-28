import { describe, expect, it } from 'vitest';
import { parseDeviceConfig, subnetFromAddress } from './network-config';

describe('network configuration normalization', () => {
  it('parses Palo Alto firewall set commands', () => {
    const result = parseDeviceConfig('palo_alto_firewall', `
set deviceconfig system hostname PA-EDGE
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.2/24
set network interface ethernet ethernet1/2 layer3 units ethernet1/2.10 tag 10 ip 10.10.10.1/24
set zone untrust network layer3 ethernet1/1
set zone trust network layer3 ethernet1/2.10
set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default nexthop ip-address 203.0.113.1
set rulebase security rules allow-out from trust
set rulebase security rules allow-out to untrust
set rulebase security rules allow-out source any
set rulebase security rules allow-out destination any
set rulebase security rules allow-out application any
set rulebase security rules allow-out action allow
set rulebase nat rules source-out source any
set rulebase nat rules source-out source-translation dynamic-ip-and-port interface-address interface ethernet1/1
`);
    expect(result.hostname).toBe('PA-EDGE');
    expect(result.deviceType).toBe('firewall');
    expect(result.interfaces.map((item) => item.name)).toContain('ethernet1/2.10');
    expect(result.interfaces.find((item) => item.name === 'ethernet1/2.10')?.vlanId).toBe('10');
    expect(result.routes.some((item) => item.destination === '0.0.0.0/0')).toBe(true);
    expect(result.aclRules[0]).toMatchObject({ name: 'allow-out', action: 'allow', fromZone: 'trust', toZone: 'untrust' });
    expect(result.natRules[0]).toMatchObject({ name: 'source-out', natType: 'snat' });
  });

  it('uses the Palo Alto network profile as a routed infrastructure device', () => {
    const result = parseDeviceConfig('palo_alto_network', `
set deviceconfig system hostname PA-ROUTER
set network interface ethernet ethernet1/1 layer3 ip 198.51.100.2/24
set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0
set network virtual-router default routing-table ip static-route default nexthop ip-address 198.51.100.1
`);
    expect(result.deviceType).toBe('router');
    expect(result.vendor).toBe('Palo Alto');
  });

  it('parses Palo Alto XML interfaces, policy, and destination NAT', () => {
    const result = parseDeviceConfig('palo_alto_firewall', `<config>
<devices><entry name="localhost.localdomain">
  <deviceconfig><system><hostname>PA-XML</hostname></system></deviceconfig>
  <network>
    <interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.2/24"/></ip></layer3></entry>
      <entry name="ethernet1/2"><layer3><ip><entry name="10.30.0.1/24"/></ip></layer3></entry>
    </ethernet></interface>
    <virtual-router><entry name="default"><routing-table><ip><static-route><entry name="default"><destination>0.0.0.0/0</destination><nexthop><ip-address>203.0.113.1</ip-address></nexthop><interface>ethernet1/1</interface></entry></static-route></ip></routing-table></entry></virtual-router>
  </network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="dmz"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
    <rulebase>
      <security><rules><entry name="publish-web"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source><destination><member>203.0.113.50</member></destination><application><member>web-browsing</member></application><action>allow</action></entry></rules></security>
      <nat><rules><entry name="web-dnat"><from><member>untrust</member></from><to><member>dmz</member></to><source><member>any</member></source><destination><member>203.0.113.50</member></destination><destination-translation><translated-address>10.30.0.50</translated-address><translated-port>443</translated-port></destination-translation></entry></rules></nat>
    </rulebase>
  </entry></vsys>
</entry></devices></config>`);
    expect(result.hostname).toBe('PA-XML');
    expect(result.interfaces.find((item) => item.name === 'ethernet1/2')).toMatchObject({ zone: 'dmz', role: 'dmz' });
    expect(result.aclRules[0]).toMatchObject({ name: 'publish-web', action: 'allow' });
    expect(result.natRules[0]).toMatchObject({ name: 'web-dnat', natType: 'port_mapping', translatedDestination: '10.30.0.50', translatedPort: '443' });
  });

  it('parses an OPNsense XML backup', () => {
    const result = parseDeviceConfig('opnsense_firewall', `<?xml version="1.0"?>
<opnsense>
  <system><hostname>edge-opn</hostname></system>
  <interfaces>
    <wan><enable>1</enable><if>igb0</if><ipaddr>203.0.113.10</ipaddr><subnet>24</subnet></wan>
    <lan><enable>1</enable><if>igb1</if><ipaddr>10.20.0.1</ipaddr><subnet>24</subnet></lan>
  </interfaces>
  <gateways><gateway_item><name>WAN_GW</name><gateway>203.0.113.1</gateway></gateway_item></gateways>
  <staticroutes><route><network>0.0.0.0/0</network><gateway>WAN_GW</gateway><descr>default</descr></route></staticroutes>
  <filter><rule><type>pass</type><interface>lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol><source><network>lan</network></source><destination><any/><port>443</port></destination><descr>web-out</descr></rule></filter>
  <nat><outbound><rule><interface>wan</interface><source><network>lan</network></source><target>203.0.113.10</target><descr>outbound</descr></rule></outbound></nat>
</opnsense>`);
    expect(result.hostname).toBe('edge-opn');
    expect(result.interfaces).toHaveLength(2);
    expect(result.routes[0]).toMatchObject({ destination: '0.0.0.0/0', nextHop: '203.0.113.1' });
    expect(result.aclRules[0]).toMatchObject({ action: 'allow', destinationPort: '443' });
    expect(result.natRules[0].natType).toBe('snat');
  });

  it('parses Juniper display-set firewall configuration', () => {
    const result = parseDeviceConfig('juniper_firewall', `
set system host-name SRX-01
set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.20/24
set interfaces ge-0/0/1 unit 100 vlan-id 100
set interfaces ge-0/0/1 unit 100 family inet address 10.100.0.1/24
set security zones security-zone untrust interfaces ge-0/0/0
set security zones security-zone trust interfaces ge-0/0/1.100
set routing-options static route 0.0.0.0/0 next-hop 203.0.113.1
set security policies from-zone trust to-zone untrust policy web-out match source-address any
set security policies from-zone trust to-zone untrust policy web-out match destination-address any
set security policies from-zone trust to-zone untrust policy web-out match application junos-https
set security policies from-zone trust to-zone untrust policy web-out then permit
`);
    expect(result.hostname).toBe('SRX-01');
    expect(result.interfaces.find((item) => item.name === 'ge-0/0/1.100')).toMatchObject({ vlanId: '100', zone: 'trust' });
    expect(result.routes[0].nextHop).toBe('203.0.113.1');
    expect(result.aclRules[0]).toMatchObject({ action: 'allow', fromZone: 'trust', toZone: 'untrust' });
  });

  it('parses OpenWrt UCI router and firewall sections', () => {
    const result = parseDeviceConfig('openwrt_network', `
config system
  option hostname 'openwrt-edge'
config interface 'lan'
  option device 'br-lan'
  option proto 'static'
  option ipaddr '192.168.50.1'
  option netmask '255.255.255.0'
config interface 'wan'
  option device 'eth0'
  option proto 'static'
  option ipaddr '198.51.100.2'
  option netmask '255.255.255.0'
config bridge-vlan
  option device 'br-lan'
  option vlan '50'
  list ports 'lan1:u*'
config route
  option interface 'wan'
  option target '0.0.0.0/0'
  option gateway '198.51.100.1'
config forwarding
  option src 'lan'
  option dest 'wan'
config nat
  option name 'masquerade'
  option src_ip '192.168.50.0/24'
  option target 'MASQUERADE'
`);
    expect(result.hostname).toBe('openwrt-edge');
    expect(result.deviceType).toBe('router');
    expect(result.vlans[0]).toMatchObject({ id: '50' });
    expect(result.routes[0].interface).toBe('wan');
    expect(result.aclRules[0]).toMatchObject({ action: 'allow', fromZone: 'lan', toZone: 'wan' });
    expect(result.natRules[0]).toMatchObject({ natType: 'snat' });
  });

  it('parses Cisco IOS router, VLAN, interface, route, and ACL records', () => {
    const result = parseDeviceConfig('cisco_network', `
hostname C9300-CORE
vlan 10
 name USERS
!
interface Vlan10
 ip address 10.10.10.1 255.255.255.0
 ip access-group USERS-IN in
 no shutdown
!
interface GigabitEthernet1/0/1
 switchport access vlan 10
!
interface GigabitEthernet1/0/48
 ip address 203.0.113.30 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 GigabitEthernet1/0/48 203.0.113.1
ip access-list extended USERS-IN
 10 permit tcp 10.10.10.0 0.0.0.255 any eq 443
 20 deny ip any any
!`);
    expect(result.hostname).toBe('C9300-CORE');
    expect(result.deviceType).toBe('router');
    expect(result.vlans.find((item) => item.id === '10')?.name).toBe('USERS');
    expect(result.routes[0]).toMatchObject({
      destination: '0.0.0.0/0',
      interface: 'GigabitEthernet1/0/48',
      nextHop: '203.0.113.1',
    });
    expect(result.aclRules).toHaveLength(2);
    expect(result.aclRules[0]).toMatchObject({ action: 'allow', destinationPort: '443', interface: 'Vlan10', direction: 'inbound' });
  });

  it('normalizes Cisco standard ACL operands as sources rather than protocols', () => {
    const result = parseDeviceConfig('cisco_network', `
hostname BRANCH
access-list 10 permit 10.20.0.0 0.0.255.255
access-list 10 deny any
`);
    expect(result.aclRules[0]).toMatchObject({ protocol: 'any', source: '10.20.0.0/16', destination: 'any', action: 'allow' });
    expect(result.aclRules[1]).toMatchObject({ source: 'any', action: 'deny' });
  });

  it('canonicalizes IPv4 interface CIDRs into network CIDRs', () => {
    expect(subnetFromAddress('192.168.10.193/26')).toBe('192.168.10.192/26');
  });
});
