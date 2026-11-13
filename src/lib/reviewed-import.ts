/**
 * The reviewed-import round trip shared by the quick-entry screens (capture
 * processing, IOC paste): a `dfir-investigator-partial` document is
 * previewed by the core, re-validated against the case, and applied as one
 * attributed commit. Nothing is written until `applyReviewed`.
 */
import { invoke } from '@/lib/api';
import type {
  ApiResponse, JsonValue, PartialApplySummary, PartialImportPreview, PartialSelectionValidation,
} from '@/types';

export interface PartialChange {
  change_id: string;
  entity_type: string;
  operation: 'create' | 'update' | 'upsert';
  target_id?: string;
  values: Record<string, JsonValue | undefined>;
}

export function partialDocument(caseId: string, source: string, changes: PartialChange[]): string {
  return JSON.stringify({ format: 'dfir-investigator-partial', format_version: 1, case_id: caseId, source, changes });
}

export async function previewDocument(document: string): Promise<PartialImportPreview> {
  const response = await invoke<ApiResponse<PartialImportPreview>>('preview_partial_import_text', { jsonData: document });
  if (!response.success || !response.data) throw new Error(response.error || 'Could not prepare the changes');
  return response.data;
}

/** Valid creates and updates — everything a quick-entry preview applies. */
export function applicableChangeIds(preview: PartialImportPreview): string[] {
  return preview.changes
    .filter((change) => change.valid && (change.operation === 'create' || change.operation === 'update'))
    .map((change) => change.id);
}

export async function applyReviewed(preview: PartialImportPreview, selectedChangeIds = applicableChangeIds(preview)): Promise<PartialApplySummary> {
  if (!selectedChangeIds.length) throw new Error('Nothing to apply: every proposed record is unchanged or invalid');
  const validation = await invoke<ApiResponse<PartialSelectionValidation>>('validate_pending_partial_import', {
    previewId: preview.preview_id,
    selectedChangeIds,
  });
  if (!validation.success || !validation.data?.valid) {
    throw new Error(validation.data?.errors.join('; ') || validation.error || 'The selection is no longer valid');
  }
  const response = await invoke<ApiResponse<PartialApplySummary>>('apply_pending_partial_import', {
    previewId: preview.preview_id,
    selectedChangeIds,
  });
  if (!response.success || !response.data) throw new Error(response.error || 'Could not apply the changes');
  return response.data;
}

export async function discardPreview(previewId: string): Promise<void> {
  await invoke<ApiResponse<boolean>>('discard_pending_partial_import', { previewId }).catch(() => undefined);
}

export function firstLine(text: string, limit = 80): string {
  const line = text.split(/\r?\n/).map((item) => item.trim()).find(Boolean) ?? '';
  return line.length > limit ? `${line.slice(0, limit - 1)}…` : line;
}
