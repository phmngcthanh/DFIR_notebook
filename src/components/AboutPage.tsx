import { GitCompareArrows, GitGraph, HardDrive, LockKeyhole, ShieldCheck } from 'lucide-react';
import { branding } from '@/config/branding';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const capabilities = [
  [HardDrive, 'One encrypted case file', 'Case data stays in an embedded SQLCipher case file held by the team\'s server; no separate database service is required.'],
  [LockKeyhole, 'Password-only access', 'The case password is the sole credential — no accounts, no roles. Export passwords are independent of it.'],
  [GitCompareArrows, 'Attributed shared editing', 'Everyone edits the same case; each change carries its expert name, and offline bundles can still be reviewed and merged in one transaction.'],
  [GitGraph, 'Shared operational picture', 'Zones, devices, NICs, connections, firewalls, evidence, and clock-corrected events stay connected.'],
] as const;

export default function AboutPage() {
  return <div className="mx-auto max-w-5xl space-y-6 p-8">
    <div className="rounded-xl bg-slate-900 p-8 text-white">
      <ShieldCheck size={42} className="mb-4 text-cyan-400" />
      <h2 className="text-3xl font-bold">{branding.productName}</h2>
      <p className="mt-2 text-cyan-200">{branding.tagline}</p>
      <p className="mt-5 max-w-3xl text-sm leading-6 text-slate-300">{branding.about}</p>
    </div>
    <div className="grid gap-4 md:grid-cols-2">{capabilities.map(([Icon, title, text]) => <Card key={title}><CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-base"><Icon size={18} className="text-cyan-600" />{title}</CardTitle></CardHeader><CardContent className="text-sm leading-6 text-slate-600">{text}</CardContent></Card>)}</div>
    <Card><CardContent className="grid gap-3 p-5 text-sm sm:grid-cols-2">
      <Info label="Organization" value={branding.organization} />
      <Info label="Application version" value={branding.version} />
      <Info label="Support" value={branding.supportEmail} />
      <Info label="Website" value={branding.website || 'Not configured'} />
      <div className="sm:col-span-2"><Info label="Copyright / legal notice" value={branding.copyright} /></div>
    </CardContent></Card>
  </div>;
}

function Info({ label, value }: { label: string; value: string }) {
  return <div><div className="text-xs uppercase tracking-wide text-slate-400">{label}</div><div className="mt-1 text-slate-700">{value}</div></div>;
}
