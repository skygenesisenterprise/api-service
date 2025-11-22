"use client";

import { motion } from "framer-motion";
import { GeneralSection } from "./sections/GeneralSection";
import { AccessSection } from "./sections/AccessSection";
import { AuthSection } from "./sections/AuthSection";
import { ApiKeysSection } from "./sections/ApiKeysSection";
import { AuditSection } from "./sections/AuditSection";
import { BillingSection } from "./sections/BillingSection";
import { AdvancedSection } from "./sections/AdvancedSection";
import type { SettingsState, SettingsActions } from "../types/settings";

interface SettingsContentProps extends SettingsState, SettingsActions {}

export function SettingsContent({
  activeSection,
  organization,
  members,
  apiKeys,
  auditLogs,
  showApiKey,
  setOrganization,
  setMembers,
  setApiKeys,
  setAuditLogs,
  setShowApiKey,
  handleSave,
  copyToClipboard,
  regenerateApiKey,
  revokeApiKey,
  hasChanges,
  isSaving,
}: SettingsContentProps) {
  const renderContent = () => {
    switch (activeSection) {
      case "organization":
      case "workspace":
      case "branding":
        return (
          <GeneralSection
            activeSection={activeSection}
            organization={organization}
            setOrganization={setOrganization}
            hasChanges={hasChanges}
            isSaving={isSaving}
            handleSave={handleSave}
          />
        );

      case "members":
      case "roles":
      case "api-policy":
        return (
          <AccessSection
            activeSection={activeSection}
            members={members}
            setMembers={setMembers}
          />
        );

      case "password-policy":
      case "mfa":
      case "sso":
      case "session":
        return <AuthSection activeSection={activeSection} />;

      case "keys-list":
      case "create-key":
        return (
          <ApiKeysSection
            activeSection={activeSection}
            apiKeys={apiKeys}
            showApiKey={showApiKey}
            setShowApiKey={setShowApiKey}
            setApiKeys={setApiKeys}
            copyToClipboard={copyToClipboard}
            regenerateApiKey={regenerateApiKey}
            revokeApiKey={revokeApiKey}
          />
        );

      case "logs":
      case "export":
        return <AuditSection auditLogs={auditLogs} />;

      case "plan":
      case "usage":
      case "invoices":
        return <BillingSection activeSection={activeSection} />;

      case "webhooks":
      case "retention":
      case "encryption":
      case "danger-zone":
        return <AdvancedSection activeSection={activeSection} />;

      default:
        return (
          <div className="space-y-6">
            <div className="text-center py-12">
              <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">Choose a settings category</h3>
              <p className="text-gray-600">Select a category from the sidebar to configure settings</p>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="flex-1 overflow-auto">
        <div className="p-4 lg:p-8">
          <motion.div
            key={activeSection}
            initial={{ opacity: 0, y: 20, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ 
              duration: 0.3, 
              ease: [0.4, 0, 0.2, 1],
              staggerChildren: 0.1
            }}
            className="space-y-6"
          >
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              {renderContent()}
            </motion.div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}