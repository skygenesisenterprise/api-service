"use client";

import { useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { toast } from "sonner";
import type { SettingsState, SettingsActions, Organization, Member, ApiKey, AuditLog } from "../types/settings";

// Mock data
const mockOrganization: Organization = {
  id: "org_123",
  name: "Sky Genesis Enterprise",
  workspaceName: "Production Workspace",
  accentColor: "#3b82f6",
  timezone: "UTC",
  locale: "en"
};

const mockMembers: Member[] = [
  {
    id: "1",
    name: "Alexandre Martin",
    email: "alex.martin@skygenesis.com",
    role: "admin",
    status: "active",
    lastActivity: new Date(Date.now() - 2 * 60 * 1000),
    avatar: "AM"
  },
  {
    id: "2",
    name: "Sophie Dubois",
    email: "sophie.dubois@skygenesis.com",
    role: "developer",
    status: "active",
    lastActivity: new Date(Date.now() - 30 * 60 * 1000),
    avatar: "SD"
  },
  {
    id: "3",
    name: "Thomas Bernard",
    email: "thomas.bernard@skygenesis.com",
    role: "auditor",
    status: "pending",
    lastActivity: new Date(Date.now() - 60 * 60 * 1000),
    avatar: "TB"
  }
];

const mockApiKeys: ApiKey[] = [
  {
    id: "1",
    name: "Production API Key",
    key: "sk_live_51H1K2j2eFvB4X9Y8wLmQpN7rT3uV6iK",
    createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    lastUsed: new Date(Date.now() - 2 * 60 * 60 * 1000),
    permissions: ["read", "write", "admin"]
  },
  {
    id: "2",
    name: "Development API Key",
    key: "sk_test_51H1K2j2eFvB4X9Y8wLmQpN7rT3uV6iK",
    createdAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    lastUsed: new Date(Date.now() - 30 * 60 * 1000),
    permissions: ["read", "write"]
  }
];

const mockAuditLogs: AuditLog[] = [
  {
    id: "1",
    user: "Alexandre Martin",
    action: "Updated organization settings",
    timestamp: new Date(Date.now() - 30 * 60 * 1000),
    ip: "192.168.1.100",
    category: "config"
  },
  {
    id: "2",
    user: "Sophie Dubois",
    action: "Generated new API key",
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
    ip: "10.0.0.45",
    category: "security"
  }
];

export function useSettingsState(): SettingsState & SettingsActions {
  const searchParams = useSearchParams();
  const router = useRouter();

  const [organization, setOrganizationState] = useState(mockOrganization);
  const [members, setMembersState] = useState(mockMembers);
  const [apiKeys, setApiKeysState] = useState(mockApiKeys);
  const [auditLogs, setAuditLogsState] = useState(mockAuditLogs);
  const [activeSection, setActiveSectionState] = useState(() => {
    const tab = searchParams.get("tab");
    return tab || "organization";
  });
  const [collapsedCategories, setCollapsedCategories] = useState<string[]>([]);
  const [hasChanges, setHasChanges] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [showApiKey, setShowApiKeyState] = useState<string | null>(null);

  const setActiveSection = useCallback((section: string) => {
    setActiveSectionState(section);
    const params = new URLSearchParams(searchParams);
    params.set("tab", section);
    router.push(`/settings?${params.toString()}`);
  }, [searchParams, router]);

  const toggleCategory = useCallback((categoryId: string) => {
    setCollapsedCategories(prev => 
      prev.includes(categoryId) 
        ? prev.filter(id => id !== categoryId)
        : [...prev, categoryId]
    );
  }, []);

  const setOrganization = useCallback((updates: Partial<Organization>) => {
    setOrganizationState(prev => ({ ...prev, ...updates }));
    setHasChanges(true);
  }, []);

  const setMembers = useCallback((newMembers: Member[]) => {
    setMembersState(newMembers);
  }, []);

  const setApiKeys = useCallback((newKeys: ApiKey[]) => {
    setApiKeysState(newKeys);
  }, []);

  const setAuditLogs = useCallback((newLogs: AuditLog[]) => {
    setAuditLogsState(newLogs);
  }, []);

  const setShowApiKey = useCallback((keyId: string | null) => {
    setShowApiKeyState(keyId);
  }, []);

  const handleSave = useCallback(async () => {
    setIsSaving(true);
    await new Promise(resolve => setTimeout(resolve, 1500));
    setIsSaving(false);
    setHasChanges(false);
    toast.success("Settings saved successfully!");
  }, []);

  const copyToClipboard = useCallback((text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard!");
  }, []);

  const regenerateApiKey = useCallback(async (_keyId: string) => {
    setIsSaving(true);
    await new Promise(resolve => setTimeout(resolve, 1000));
    setIsSaving(false);
    toast.success("API key regenerated successfully!");
  }, []);

  const revokeApiKey = useCallback((keyId: string) => {
    setApiKeysState(prev => prev.filter(key => key.id !== keyId));
    toast.success("API key revoked successfully!");
  }, []);

  return {
    // State
    organization,
    members,
    apiKeys,
    auditLogs,
    activeSection,
    collapsedCategories,
    hasChanges,
    isSaving,
    showApiKey,
    
    // Actions
    setActiveSection,
    toggleCategory,
    setOrganization,
    setMembers,
    setApiKeys,
    setAuditLogs,
    setShowApiKey,
    handleSave,
    copyToClipboard,
    regenerateApiKey,
    revokeApiKey,
  };
}