import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { ParsedDeviceConfig } from '@/lib/network-config';

export default function ImportedDeviceDetails({ config }: { config: ParsedDeviceConfig }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1">
        <Badge>{config.vendor}</Badge>
        <Badge variant="outline">{config.deviceType}</Badge>
        <Badge variant="outline">{config.profile.replaceAll('_', ' ')}</Badge>
      </div>
      <InventorySection title={`Interfaces (${config.interfaces.length})`}>
        <Table>
          <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Zone / VLAN</TableHead><TableHead>Addresses</TableHead></TableRow></TableHeader>
          <TableBody>{config.interfaces.length ? config.interfaces.map((item) => (
            <TableRow key={item.name} className={!item.enabled ? 'opacity-50' : ''}>
              <TableCell className="font-medium">{item.name}</TableCell>
              <TableCell>{item.zone ?? (item.vlanId ? `VLAN ${item.vlanId}` : item.role)}</TableCell>
              <TableCell className="font-mono text-[11px]">{item.addresses.join(', ') || 'L2 / unresolved'}</TableCell>
            </TableRow>
          )) : <EmptyRow columns={3} />}</TableBody>
        </Table>
      </InventorySection>
      <InventorySection title={`VLAN list (${config.vlans.length})`}>
        <Table>
          <TableHeader><TableRow><TableHead>VLAN</TableHead><TableHead>Name</TableHead><TableHead>Ports / subnet</TableHead></TableRow></TableHeader>
          <TableBody>{config.vlans.length ? config.vlans.map((item) => (
            <TableRow key={item.id}>
              <TableCell className="font-mono">{item.id}</TableCell>
              <TableCell className="font-medium">{item.name}</TableCell>
              <TableCell className="text-[11px]">{item.interfaces.join(', ') || '—'}{item.subnet ? ` · ${item.subnet}` : ' · subnet unresolved'}</TableCell>
            </TableRow>
          )) : <EmptyRow columns={3} />}</TableBody>
        </Table>
      </InventorySection>
      <InventorySection title={`Routing list (${config.routes.length})`}>
        <Table>
          <TableHeader><TableRow><TableHead>Destination</TableHead><TableHead>Next hop</TableHead><TableHead>Interface</TableHead></TableRow></TableHeader>
          <TableBody>{config.routes.length ? config.routes.map((item, index) => (
            <TableRow key={`${item.name}-${index}`} className={!item.active ? 'opacity-50' : ''}>
              <TableCell className="font-mono text-[11px]">{item.destination}</TableCell>
              <TableCell className="font-mono text-[11px]">{item.nextHop ?? '—'}</TableCell>
              <TableCell>{item.interface ?? item.protocol}</TableCell>
            </TableRow>
          )) : <EmptyRow columns={3} />}</TableBody>
        </Table>
      </InventorySection>
      <InventorySection title={`ACL / policy list (${config.aclRules.length})`}>
        <Table>
          <TableHeader><TableRow><TableHead>Rule</TableHead><TableHead>Action</TableHead><TableHead>Source → destination</TableHead></TableRow></TableHeader>
          <TableBody>{config.aclRules.length ? config.aclRules.map((item, index) => (
            <TableRow key={`${item.name}-${item.sequence}-${index}`} className={!item.enabled ? 'opacity-50' : ''}>
              <TableCell><div className="font-medium">{item.name}</div><div className="text-[10px] text-slate-400">#{item.sequence} · {item.protocol}</div></TableCell>
              <TableCell><Badge variant={item.action === 'deny' ? 'destructive' : 'outline'}>{item.action}</Badge></TableCell>
              <TableCell className="font-mono text-[11px]">{item.source}{item.sourcePort ? `:${item.sourcePort}` : ''} → {item.destination}{item.destinationPort ? `:${item.destinationPort}` : ''}</TableCell>
            </TableRow>
          )) : <EmptyRow columns={3} />}</TableBody>
        </Table>
      </InventorySection>
      <InventorySection title={`NAT / firewall translation list (${config.natRules.length})`}>
        <Table>
          <TableHeader><TableRow><TableHead>Rule</TableHead><TableHead>Type</TableHead><TableHead>Translation</TableHead></TableRow></TableHeader>
          <TableBody>{config.natRules.length ? config.natRules.map((item, index) => (
            <TableRow key={`${item.name}-${index}`} className={!item.enabled ? 'opacity-50' : ''}>
              <TableCell className="font-medium">{item.name}</TableCell>
              <TableCell>{item.natType}</TableCell>
              <TableCell className="font-mono text-[11px]">
                {item.translatedSource ? `src → ${item.translatedSource}` : ''}
                {item.translatedSource && item.translatedDestination ? '; ' : ''}
                {item.translatedDestination ? `dst → ${item.translatedDestination}${item.translatedPort ? `:${item.translatedPort}` : ''}` : ''}
              </TableCell>
            </TableRow>
          )) : <EmptyRow columns={3} />}</TableBody>
        </Table>
      </InventorySection>
      {config.warnings.length > 0 && (
        <div className="rounded border border-amber-200 bg-amber-50 p-2 text-[11px] text-amber-900">
          {config.warnings.map((warning) => <div key={warning}>• {warning}</div>)}
        </div>
      )}
    </div>
  );
}

function InventorySection({ title, children }: { title: string; children: React.ReactNode }) {
  return <details className="rounded border bg-white" open><summary className="cursor-pointer px-2 py-1.5 text-xs font-medium">{title}</summary><div className="max-h-56 overflow-auto border-t">{children}</div></details>;
}

function EmptyRow({ columns }: { columns: number }) {
  return <TableRow><TableCell colSpan={columns} className="py-3 text-center text-xs text-slate-400">No entries recognized.</TableCell></TableRow>;
}
