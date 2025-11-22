"use client";

import { useState } from "react";
import { Menu, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SettingsSidebar } from "./SettingsSidebar";
import { SettingsContent } from "./SettingsContent";
import { useSettingsState } from "../hooks/useSettingsState";

export function SettingsLayout() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const settingsState = useSettingsState();

  return (
    <div className="flex h-screen bg-gray-50 relative">
      {/* Mobile Menu Button */}
      <div className="lg:hidden fixed top-4 left-4 z-50">
        <Button
          variant="outline"
          size="sm"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          className="bg-white shadow-md"
        >
          {isMobileMenuOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
        </Button>
      </div>

      {/* Sidebar - Desktop: Fixed, Mobile: Overlay */}
      <div className={`
        ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'} 
        lg:translate-x-0 fixed lg:relative z-40 transition-transform duration-300 ease-in-out
        h-full lg:h-auto
      `}>
        <SettingsSidebar
          activeSection={settingsState.activeSection}
          collapsedCategories={settingsState.collapsedCategories}
          onSectionChange={(section) => {
            settingsState.setActiveSection(section);
            setIsMobileMenuOpen(false); // Close mobile menu after selection
          }}
          onToggleCategory={settingsState.toggleCategory}
          isMobileMenuOpen={isMobileMenuOpen}
          setIsMobileMenuOpen={setIsMobileMenuOpen}
        />
      </div>

      {/* Mobile Overlay */}
      {isMobileMenuOpen && (
        <div 
          className="lg:hidden fixed inset-0 bg-black bg-opacity-50 z-30"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Main Content */}
      <div className="flex-1 lg:ml-0 overflow-hidden">
        <SettingsContent {...settingsState} />
      </div>
    </div>
  );
}