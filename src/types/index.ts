export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export interface Case {
  id: string;
  name: string;
  description: string;
  client_name: string;
  investigator: string;
  status: 'active' | 'closed' | 'archived';
  created_at: string;
  updated_at: string;
  metadata?: string;
}

export interface Network {
  id: string;
  name: string;
  subnet: string;
  network_type: string;
  description: string;
  vlan_id?: string;
  created_at: string;
}

export type CompromiseStatus = 'unknown' | 'clean' | 'suspected' | 'infected';
export type InvestigationStatus = 'not_started' | 'in_progress' | 'completed';

export interface Asset {
  id: string;
  network_id?: string;
  network_name?: string;
  name: string;
  ip_address: string;
  mac_address?: string;
  asset_type: string;
  os?: string;
  user_name?: string;
  suspicious: boolean;
  compromise_status: CompromiseStatus;
  investigation_status: InvestigationStatus;
  properties?: string;
  scan_results?: string;
  created_at: string;
}

export interface NetworkInterface {
  id: string;
  asset_id: string;
  name: string;
  ip_address: string;
  mac_address?: string;
  network_id?: string;
  network_name?: string;
  is_primary: boolean;
}

export interface TimelineEvent {
  id: string;
  asset_id?: string;
  asset_name?: string;
  timestamp: string;
  raw_timestamp?: string;
  raw_timezone?: string;
  server_timestamp_utc?: string;
  correct_timestamp_raw?: string;
  correct_timezone?: string;
  clock_profile_id?: string;
  clock_profile_name?: string;
  clock_offset_ms: number;
  time_precision: string;
  correct_time_precision: string;
  event_type: string;
  description: string;
  severity: string;
  source?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  created_at: string;
}

export interface ClockProfile {
  id: string;
  name: string;
  description: string;
  server_reference_raw: string;
  server_timezone: string;
  server_reference_utc: string;
  correct_reference_raw: string;
  correct_timezone: string;
  correct_reference_utc: string;
  offset_ms: number;
  created_at: string;
  updated_at: string;
}

export interface TimePreview {
  input: string;
  timezone: string;
  interpreted_utc: string;
  corrected_utc: string;
  precision: string;
  epoch_millis: number;
  offset_ms: number;
  used_embedded_timezone: boolean;
}

export interface Note {
  id: string;
  title: string;
  content: string;
  created_at: string;
  updated_at: string;
}

export interface Ioc {
  id: string;
  ioc_type: string;
  value: string;
  description: string;
  threat_level: string;
  first_seen?: string;
  last_seen?: string;
  created_at: string;
}

export interface Firewall {
  id: string;
  network_id?: string;
  network_name?: string;
  name: string;
  vendor?: string;
  model?: string;
  rules?: string;
  config_text?: string;
  created_at: string;
}

export interface FirewallInterface {
  id: string;
  firewall_id: string;
  name: string;
  ip_addresses: string[];
  mac_address?: string;
  network_id?: string;
  network_name?: string;
  vlan_id?: string;
  role: 'wan' | 'lan' | 'dmz' | 'management' | 'ha' | 'vpn' | 'other';
  is_primary: boolean;
  description: string;
}

export interface FirewallNatRule {
  id: string;
  firewall_id: string;
  name: string;
  nat_type: 'vip' | 'dnat' | 'snat' | 'port_mapping';
  enabled: boolean;
  protocol: 'any' | 'tcp' | 'udp' | 'icmp' | 'sctp' | 'other';
  source_cidr?: string;
  original_destination?: string;
  original_port?: string;
  translated_source?: string;
  translated_destination?: string;
  translated_port?: string;
  inbound_interface_id?: string;
  outbound_interface_id?: string;
  description: string;
  created_at: string;
}

export interface NetworkConnection {
  id: string;
  source_network_id: string;
  source_network_name?: string;
  target_network_id: string;
  target_network_name?: string;
  connection_type: string;
  description: string;
  device_name?: string;
}

export interface ExpertIdentity {
  name: string;
  session_id: string;
  scope_label?: string;
  scope_network_ids: string[];
}

export interface HistoryChange {
  id: string;
  entity_type: string;
  entity_id: string;
  operation: 'create' | 'update' | 'delete';
  base_revision: number;
  new_revision: number;
  before?: JsonValue;
  after?: JsonValue;
  source_change_id?: string;
  created_at: string;
}

export interface HistoryCommit {
  id: string;
  author_name: string;
  session_id: string;
  message: string;
  scope?: JsonValue;
  created_at: string;
  parent_ids: string[];
  changes: HistoryChange[];
}

export interface FieldDiff {
  field: string;
  base?: JsonValue;
  local?: JsonValue;
  incoming?: JsonValue;
  conflict: boolean;
}

export type MergeClassification = 'clean' | 'auto_mergeable' | 'conflict' | 'delete_conflict' | 'already_applied';

export interface MergePreviewChange {
  id: string;
  source_change_ids: string[];
  entity_type: string;
  entity_id: string;
  operation: 'create' | 'update' | 'delete';
  classification: MergeClassification;
  author_name: string;
  message: string;
  scope?: JsonValue;
  before?: JsonValue;
  local?: JsonValue;
  incoming?: JsonValue;
  suggested?: JsonValue;
  fields: FieldDiff[];
}

export interface MergePreview {
  bundle_id: string;
  case_id: string;
  base_commit_id: string;
  head_commit_id: string;
  exported_by: string;
  exported_at: string;
  common_base: boolean;
  changes: MergePreviewChange[];
}

export interface MergeDecision {
  change_id: string;
  selected: boolean;
  resolved_after?: JsonValue;
}

export interface MergeApplySummary {
  applied: number;
  skipped: number;
  merge_commit_id?: string;
}

export interface ImportSummary {
  entities: Record<string, { inserted: number; skipped: number }>;
}

export interface PartialFieldDiff {
  field: string;
  current?: JsonValue;
  incoming?: JsonValue;
}

export interface PartialImportPreviewChange {
  id: string;
  entity_type: string;
  entity_id: string;
  operation: 'create' | 'update' | 'unchanged' | 'invalid';
  title: string;
  valid: boolean;
  error?: string;
  recommended_selected: boolean;
  before?: JsonValue;
  after?: JsonValue;
  fields: PartialFieldDiff[];
}

export interface PartialImportPreview {
  preview_id: string;
  case_id: string;
  source: string;
  source_kind: 'partial' | 'snapshot';
  changes: PartialImportPreviewChange[];
  warnings: string[];
}

export interface PartialSelectionValidation {
  valid: boolean;
  errors: string[];
  selected_count: number;
  create_count: number;
  update_count: number;
}

export interface PartialApplySummary {
  created: number;
  updated: number;
  entities: Record<string, number>;
  commit_id?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export type View = 'dashboard' | 'networks' | 'assets' | 'topology' | 'timeline' | 'iocs' | 'notes' | 'export' | 'about';
