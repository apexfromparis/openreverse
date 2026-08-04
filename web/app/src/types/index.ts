// ============================================================================
// OpenReverse Studio — TypeScript Domain Interfaces & Types
// ============================================================================

export interface TerminalCommand {
  cmd: string;
  label: string;
  iconName: string;
  description: string;
  outputHTML: string;
}

export interface PluginItem {
  id: string;
  author: string;
  title: string;
  description: string;
  category: 'Security' | 'Analysis' | 'Crackme' | 'Kernel';
  tier: 'FREE' | 'PRO' | 'CREATOR';
  installs: string;
  installCommand: string;
}

export interface UserAuth {
  isLoggedIn: boolean;
  provider?: 'GitHub' | 'Google';
  username?: string;
  email?: string;
  avatarUrl?: string;
  tier?: 'COMMUNITY_FREE' | 'PRO_ANALYST' | 'DEV_CREATOR_PRO' | 'ADMIN';
  licenseToken?: string;
}

export interface DecompileSnippet {
  address: string;
  assemblyLines: {
    addr: string;
    mnemonic: string;
    operands: string;
    comment?: string;
  }[];
  cCode: string;
  aiNotes: string[];
}
