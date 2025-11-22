// Settings type definitions
export interface Organization {
  id: string;
  name: string;
  workspaceName: string;
  logo?: string;
  accentColor: string;
  timezone: string;
  locale: string;
}

export interface Member {
  id: string;
  name: string;
  email: string;
  role: "admin" | "developer" | "auditor";
  status: "active" | "pending" | "inactive";
  lastActivity: Date;
  avatar?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key: string;
  createdAt: Date;
  lastUsed?: Date;
  permissions: string[];
}

export interface AuditLog {
  id: string;
  user: string;
  action: string;
  timestamp: Date;
  ip: string;
  category: "auth" | "config" | "billing" | "security" | "api";
}

export interface NavigationItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

export interface NavigationCategory {
  id: string;
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavigationItem[];
}

export interface SettingsState {
  organization: Organization;
  members: Member[];
  apiKeys: ApiKey[];
  auditLogs: AuditLog[];
  activeSection: string;
  collapsedCategories: string[];
  hasChanges: boolean;
  isSaving: boolean;
  showApiKey: string | null;
}

export interface SettingsActions {
  setActiveSection: (section: string) => void;
  toggleCategory: (categoryId: string) => void;
  setOrganization: (org: Partial<Organization>) => void;
  setMembers: (members: Member[]) => void;
  setApiKeys: (keys: ApiKey[]) => void;
  setAuditLogs: (logs: AuditLog[]) => void;
  setShowApiKey: (keyId: string | null) => void;
  handleSave: () => Promise<void>;
  copyToClipboard: (text: string) => void;
  regenerateApiKey: (keyId: string) => Promise<void>;
  revokeApiKey: (keyId: string) => void;
}