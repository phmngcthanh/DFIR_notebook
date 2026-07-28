import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import ConnectivityVerifier from './ConnectivityVerifier';
import type { ConnectivityInventory } from '@/lib/connectivity-analysis';
import type { ParsedDeviceConfig } from '@/lib/network-config';

vi.mock('@/lib/api', () => ({ invoke: vi.fn() }));

const config: ParsedDeviceConfig = {
  schema: 'dfir-network-config-v1',
  profile: 'palo_alto_firewall',
  vendor: 'Palo Alto',
  deviceType: 'firewall',
  hostname: 'edge',
  rawConfig: 'fixture',
  interfaces: [
    { name: 'wan', addresses: ['203.0.113.2/24'], zone: 'untrust', role: 'wan', enabled: true },
    { name: 'lan', addresses: ['10.0.0.1/24'], zone: 'trust', role: 'lan', enabled: true },
  ],
  vlans: [],
  routes: [{ name: 'default', destination: '0.0.0.0/0', interface: 'wan', nextHop: '203.0.113.1', protocol: 'static', active: true }],
  aclRules: [
    { name: 'out', sequence: 10, action: 'allow', protocol: 'any', source: 'any', destination: 'any', fromZone: 'trust', toZone: 'untrust', enabled: true },
    { name: 'in', sequence: 20, action: 'deny', protocol: 'any', source: 'any', destination: 'any', fromZone: 'untrust', toZone: 'trust', enabled: true },
  ],
  natRules: [{ name: 'snat', natType: 'snat', protocol: 'any', source: '10.0.0.0/24', translatedSource: '203.0.113.2', enabled: true }],
  warnings: [],
};

const inventory: ConnectivityInventory = {
  networks: [
    { id: 'lan', name: 'Users', subnet: '10.0.0.0/24', network_type: 'LAN', description: '', created_at: '' },
    { id: 'wan', name: 'WAN', subnet: '203.0.113.0/24', network_type: 'WAN', description: '', created_at: '' },
  ],
  connections: [],
  assets: [],
  networkInterfaces: [],
  firewalls: [{ id: 'fw', name: 'edge', rules: JSON.stringify(config), created_at: '' }],
  firewallInterfaces: [
    { id: 'wan-if', firewall_id: 'fw', name: 'wan', ip_addresses: ['203.0.113.2/24'], network_id: 'wan', role: 'wan', is_primary: true, description: '' },
    { id: 'lan-if', firewall_id: 'fw', name: 'lan', ip_addresses: ['10.0.0.1/24'], network_id: 'lan', role: 'lan', is_primary: false, description: '' },
  ],
  firewallNatRules: [],
};

describe('ConnectivityVerifier', () => {
  it('keeps compliance and path discovery separate and renders path evidence', async () => {
    const user = userEvent.setup();
    render(
      <ConnectivityVerifier
        caseInfo={{
          id: 'case-1',
          name: 'Incident',
          description: '',
          client_name: '',
          investigator: '',
          status: 'active',
          created_at: '',
          updated_at: '',
        }}
        inventory={inventory}
        onChanged={vi.fn()}
        onClose={vi.fn()}
      />,
    );

    expect(screen.getByText(/Define what must be connected or isolated/)).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: '2. Actual path analysis' }));
    expect(screen.getByText(/Find every simple path/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Find paths' }));

    expect(screen.getByText(/outbound: Users → Internet/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Allowed by out/).length).toBeGreaterThan(0);
    expect(screen.getByText(/inbound: Internet → Users/i)).toBeInTheDocument();
    expect(screen.getByText('No logical path was found in the imported model.')).toBeInTheDocument();
  });
});
