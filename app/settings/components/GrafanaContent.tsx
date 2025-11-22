"use client";

import { motion, AnimatePresence } from "framer-motion";
import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { GrafanaGeneralSection } from "./sections/GrafanaGeneralSection";
import { AccessSection } from "./sections/AccessSection";
import { AuthSection } from "./sections/AuthSection";
import { ApiKeysSection } from "./sections/ApiKeysSection";
import { AuditSection } from "./sections/AuditSection";
import { BillingSection } from "./sections/BillingSection";
import { AdvancedSection } from "./sections/AdvancedSection";
import { navigationCategories } from "../data/navigationConfig";
import type { SettingsState, SettingsActions } from "../types/settings";

interface GrafanaContentProps extends SettingsState, SettingsActions {
  isMobileMenuOpen: boolean;
  setIsMobileMenuOpen: (open: boolean) => void;
}

export function GrafanaContent({
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
  isMobileMenuOpen,
  setIsMobileMenuOpen,
}: GrafanaContentProps) {
  
  const renderContent = () => {
    switch (activeSection) {
      case "organization":
      case "workspace":
      case "branding":
        return (
          <GrafanaGeneralSection
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
          <div className="flex flex-col items-center justify-center h-96">
            <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mb-4">
              <svg className="w-8 h-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-900 mb-2">Choisir une catégorie</h3>
            <p className="text-gray-600 text-center max-w-md">
              Sélectionnez une catégorie dans la barre latérale pour configurer les paramètres
            </p>
          </div>
        );
    }
  };

  return (
    <div className="flex-1 flex flex-col min-h-screen bg-gray-50">
      {/* Top Bar */}
      <header className="bg-white border-b border-gray-200 px-4 lg:px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="lg:hidden"
            >
              <Menu className="w-4 h-4" />
            </Button>
            <div>
              <h2 className="text-xl font-semibold text-gray-900">
                {navigationCategories.find(cat => 
                  cat.items.some(item => item.id === activeSection)
                )?.title || "Settings"}
              </h2>
              <p className="text-sm text-gray-600">
                {navigationCategories
                  .flatMap(cat => cat.items)
                  .find(item => item.id === activeSection)?.label || "Configuration"}
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            {hasChanges && (
              <Button
                onClick={handleSave}
                disabled={isSaving}
                className="bg-blue-600 hover:bg-blue-700"
              >
                {isSaving ? "Enregistrement..." : "Enregistrer les changements"}
              </Button>
            )}
          </div>
        </div>
      </header>

      {/* Main Content - Full Width */}
      <main className="flex-1 p-4 lg:p-6 max-w-none">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeSection}
            initial={{ opacity: 0, y: 20, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.98 }}
            transition={{ 
              duration: 0.3, 
              ease: [0.4, 0, 0.2, 1]
            }}
            className="w-full"
          >
            {renderContent()}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}