/**
 * Team presets offered when an expert starts a session. The team is
 * self-declared attribution like the expert name: it labels every change in
 * history and filters the Activity Board, and never restricts what anyone
 * can edit. Any other team name can be typed.
 */
export const TEAM_PRESETS = [
  'Investigator',
  'Network exploration',
  'Log analysis',
  'Malware reverse engineering',
  'Evidence collection',
] as const;

const TEAM_STORAGE_KEY = 'dfir-expert-team';

export function rememberedTeam(): string {
  try {
    return localStorage.getItem(TEAM_STORAGE_KEY) ?? '';
  } catch {
    return '';
  }
}

export function rememberTeam(team: string): void {
  try {
    if (team.trim()) localStorage.setItem(TEAM_STORAGE_KEY, team.trim());
    else localStorage.removeItem(TEAM_STORAGE_KEY);
  } catch {
    // Storage can be unavailable (private windows); the team still applies to this session.
  }
}
