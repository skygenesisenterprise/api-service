"use client";

import { useState } from "react";
import { Menu, X, Settings, ChevronDown, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { navigationCategories } from "../data/navigationConfig";

interface GrafanaSidebarProps {
  activeSection: string;
  collapsedCategories: string[];
  onSectionChange: (section: string) => void;
  onToggleCategory: (categoryId: string) => void;
  isMobileMenuOpen: boolean;
  setIsMobileMenuOpen: (open: boolean) => void;
}

export function GrafanaSidebar({
  activeSection,
  collapsedCategories,
  onSectionChange,
  onToggleCategory,
  isMobileMenuOpen,
  setIsMobileMenuOpen,
}: GrafanaSidebarProps) {
  return (
    <>
      {/* Mobile Overlay */}
      {isMobileMenuOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`
        fixed lg:relative top-0 left-0 z-50 h-screen bg-white border-r border-gray-200
        w-72 lg:w-72 transform transition-transform duration-300 ease-in-out
        ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        flex flex-col
      `}>
        
        {/* Header */}
        <div className="p-6 border-b border-gray-200 bg-gray-50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
                <Settings className="w-4 h-4 text-white" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-gray-900">Settings</h1>
                <p className="text-xs text-gray-600">Configuration</p>
              </div>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setIsMobileMenuOpen(false)}
              className="lg:hidden"
            >
              <X className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Navigation */}
        <ScrollArea className="flex-1 p-4">
          <div className="space-y-1">
            {navigationCategories.map((category) => {
              const isCollapsed = collapsedCategories.includes(category.id);
              const Icon = category.icon;
              const hasActiveItem = category.items.some(item => item.id === activeSection);
              
              return (
                <div key={category.id} className="mb-2">
                  {/* Category Header */}
                  <Button
                    variant="ghost"
                    className={`
                      w-full justify-between p-3 h-auto hover:bg-gray-50 transition-colors
                      ${hasActiveItem ? 'bg-blue-50 text-blue-700' : 'text-gray-700'}
                    `}
                    onClick={() => onToggleCategory(category.id)}
                  >
                    <div className="flex items-center gap-3">
                      <Icon className="w-4 h-4" />
                      <span className="font-medium">{category.title}</span>
                    </div>
                    {isCollapsed ? (
                      <ChevronRight className="w-4 h-4" />
                    ) : (
                      <ChevronDown className="w-4 h-4" />
                    )}
                  </Button>
                  
                  {/* Category Items */}
                  {!isCollapsed && (
                    <div className="ml-4 mt-1 space-y-1">
                      {category.items.map((item) => {
                        const ItemIcon = item.icon;
                        const isActive = activeSection === item.id;
                        
                        return (
                          <Button
                            key={item.id}
                            variant="ghost"
                            className={`
                              w-full justify-start p-2 h-auto hover:bg-gray-50 transition-colors
                              ${isActive 
                                ? 'bg-blue-100 text-blue-700 border-l-2 border-blue-600' 
                                : 'text-gray-600 hover:text-gray-900'
                              }
                            `}
                            onClick={() => {
                              onSectionChange(item.id);
                              setIsMobileMenuOpen(false);
                            }}
                          >
                            <ItemIcon className="w-4 h-4 mr-3" />
                            <span className="text-sm">{item.label}</span>
                          </Button>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </ScrollArea>
      </div>
    </>
  );
}