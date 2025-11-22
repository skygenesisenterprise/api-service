"use client";

import { useState } from "react";
import { GrafanaSidebar } from "./GrafanaSidebar";
import { GrafanaContent } from "./GrafanaContent";
import { useSettingsState } from "../hooks/useSettingsState";

export function GrafanaSettingsLayout() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const settingsState = useSettingsState();

  return (
    <div className="flex h-screen bg-gray-50 overflow-hidden">
      {/* Sidebar */}
      <GrafanaSidebar
        activeSection={settingsState.activeSection}
        collapsedCategories={settingsState.collapsedCategories}
        onSectionChange={settingsState.setActiveSection}
        onToggleCategory={settingsState.toggleCategory}
        isMobileMenuOpen={isMobileMenuOpen}
        setIsMobileMenuOpen={setIsMobileMenuOpen}
      />
      
      {/* Main Content */}
      <GrafanaContent
        {...settingsState}
        isMobileMenuOpen={isMobileMenuOpen}
        setIsMobileMenuOpen={setIsMobileMenuOpen}
      />
    </div>
  );
}