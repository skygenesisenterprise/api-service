"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Settings, Bell, Palette, Globe, Shield, Lock, Smartphone, Mail, X } from "lucide-react";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [user, setUser] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [settings, setSettings] = useState({
    // Notifications
    emailNotifications: true,
    pushNotifications: true,
    smsNotifications: false,
    securityAlerts: true,
    
    // Appearance
    theme: 'auto' as 'light' | 'dark' | 'auto',
    language: 'en',
    timezone: 'UTC',
    
    // Privacy
    profileVisibility: 'private' as 'public' | 'private' | 'organizations',
    dataSharing: false,
    twoFactorAuth: false,
  });

  useEffect(() => {
    if (isOpen) {
      // Load user data from localStorage
      const userData = localStorage.getItem("user");
      
      if (userData) {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        
        // Load settings from user preferences
        if (parsedUser.preferences) {
          setSettings({
            ...settings,
            theme: parsedUser.preferences.theme || 'auto',
            language: parsedUser.profile?.language || 'en',
            timezone: parsedUser.profile?.timezone || 'UTC',
            profileVisibility: parsedUser.preferences.privacy?.profileVisibility || 'private',
            dataSharing: parsedUser.preferences.privacy?.dataSharing || false,
            emailNotifications: parsedUser.preferences.notifications?.email || true,
            pushNotifications: parsedUser.preferences.notifications?.push || true,
            smsNotifications: parsedUser.preferences.notifications?.sms || false,
          });
        }
      }
    }
  }, [isOpen]);

  const handleSave = async () => {
    setIsLoading(true);
    try {
      // TODO: Update settings via API
      console.log("Saving settings:", settings);
      
      // For now, just update localStorage
      if (user) {
        const updatedUser = {
          ...user,
          preferences: {
            ...user.preferences,
            theme: settings.theme,
            notifications: {
              email: settings.emailNotifications,
              push: settings.pushNotifications,
              sms: settings.smsNotifications,
            },
            privacy: {
              profileVisibility: settings.profileVisibility,
              dataSharing: settings.dataSharing,
            },
          },
          profile: {
            ...user.profile,
            language: settings.language,
            timezone: settings.timezone,
          }
        };
        localStorage.setItem("user", JSON.stringify(updatedUser));
        setUser(updatedUser);
      }
    } catch (error) {
      console.error("Failed to save settings:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      onClose();
    }
  };

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    } else {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />
      
      {/* Modal Content */}
      <div className="relative z-10 w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
        <Card className="bg-white shadow-2xl">
          {/* Header */}
          <CardHeader className="flex items-center justify-between pb-4">
            <div>
              <CardTitle className="flex items-center gap-2 text-xl">
                <Settings className="h-5 w-5" />
                Settings
              </CardTitle>
              <CardDescription>Manage your account settings and preferences</CardDescription>
            </div>
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="h-8 w-8 p-0 hover:bg-gray-100"
            >
              <X className="h-4 w-4" />
            </Button>
          </CardHeader>

          <CardContent className="space-y-6">
            {user ? (
              <>
                {/* Notifications */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <Bell className="h-5 w-5" />
                    Notifications
                  </h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label htmlFor="email-notifications">Email Notifications</Label>
                        <p className="text-sm text-gray-500">Receive notifications via email</p>
                      </div>
                      <Switch
                        id="email-notifications"
                        checked={settings.emailNotifications}
                        onCheckedChange={(checked) => setSettings({ ...settings, emailNotifications: checked })}
                      />
                    </div>
                    
                    <Separator />
                    
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label htmlFor="push-notifications">Push Notifications</Label>
                        <p className="text-sm text-gray-500">Receive browser push notifications</p>
                      </div>
                      <Switch
                        id="push-notifications"
                        checked={settings.pushNotifications}
                        onCheckedChange={(checked) => setSettings({ ...settings, pushNotifications: checked })}
                      />
                    </div>
                    
                    <Separator />
                    
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label htmlFor="sms-notifications">SMS Notifications</Label>
                        <p className="text-sm text-gray-500">Receive notifications via SMS</p>
                      </div>
                      <Switch
                        id="sms-notifications"
                        checked={settings.smsNotifications}
                        onCheckedChange={(checked) => setSettings({ ...settings, smsNotifications: checked })}
                      />
                    </div>
                    
                    <Separator />
                    
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label htmlFor="security-alerts">Security Alerts</Label>
                        <p className="text-sm text-gray-500">Get notified about security events</p>
                      </div>
                      <Switch
                        id="security-alerts"
                        checked={settings.securityAlerts}
                        onCheckedChange={(checked) => setSettings({ ...settings, securityAlerts: checked })}
                      />
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Appearance */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <Palette className="h-5 w-5" />
                    Appearance
                  </h3>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="theme">Theme</Label>
                      <select
                        id="theme"
                        value={settings.theme}
                        onChange={(e) => setSettings({ ...settings, theme: e.target.value as any })}
                        className="w-full p-2 border border-gray-300 rounded-md"
                      >
                        <option value="light">Light</option>
                        <option value="dark">Dark</option>
                        <option value="auto">Auto (System)</option>
                      </select>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="language" className="flex items-center gap-2">
                          <Globe className="h-4 w-4" />
                          Language
                        </Label>
                        <select
                          id="language"
                          value={settings.language}
                          onChange={(e) => setSettings({ ...settings, language: e.target.value })}
                          className="w-full p-2 border border-gray-300 rounded-md"
                        >
                          <option value="en">English</option>
                          <option value="fr">Français</option>
                          <option value="es">Español</option>
                          <option value="de">Deutsch</option>
                          <option value="ja">日本語</option>
                        </select>
                      </div>
                      
                      <div className="space-y-2">
                        <Label htmlFor="timezone">Timezone</Label>
                        <select
                          id="timezone"
                          value={settings.timezone}
                          onChange={(e) => setSettings({ ...settings, timezone: e.target.value })}
                          className="w-full p-2 border border-gray-300 rounded-md"
                        >
                          <option value="UTC">UTC</option>
                          <option value="America/New_York">Eastern Time</option>
                          <option value="America/Los_Angeles">Pacific Time</option>
                          <option value="Europe/London">London</option>
                          <option value="Europe/Paris">Paris</option>
                          <option value="Asia/Tokyo">Tokyo</option>
                        </select>
                      </div>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Privacy */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Privacy
                  </h3>
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="profile-visibility">Profile Visibility</Label>
                      <select
                        id="profile-visibility"
                        value={settings.profileVisibility}
                        onChange={(e) => setSettings({ ...settings, profileVisibility: e.target.value as any })}
                        className="w-full p-2 border border-gray-300 rounded-md"
                      >
                        <option value="public">Public</option>
                        <option value="private">Private</option>
                        <option value="organizations">Organizations Only</option>
                      </select>
                      <p className="text-sm text-gray-500">
                        Control who can see your profile information
                      </p>
                    </div>
                    
                    <Separator />
                    
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label htmlFor="data-sharing">Data Sharing</Label>
                        <p className="text-sm text-gray-500">Share anonymous usage data to improve service</p>
                      </div>
                      <Switch
                        id="data-sharing"
                        checked={settings.dataSharing}
                        onCheckedChange={(checked) => setSettings({ ...settings, dataSharing: checked })}
                      />
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Security */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Security
                  </h3>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label htmlFor="2fa">Two-Factor Authentication</Label>
                        <p className="text-sm text-gray-500">Add an extra layer of security to your account</p>
                      </div>
                      <Button variant="outline" size="sm">
                        {settings.twoFactorAuth ? "Manage" : "Enable"}
                      </Button>
                    </div>
                    
                    <Separator />
                    
                    <div className="space-y-3">
                      <Button variant="outline" className="w-full justify-start">
                        <Lock className="h-4 w-4 mr-2" />
                        Change Password
                      </Button>
                      
                      <Button variant="outline" className="w-full justify-start">
                        <Smartphone className="h-4 w-4 mr-2" />
                        Manage Devices
                      </Button>
                      
                      <Button variant="outline" className="w-full justify-start">
                        <Mail className="h-4 w-4 mr-2" />
                        Connected Accounts
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Save Button */}
                <div className="flex justify-end pt-4 border-t">
                  <Button onClick={handleSave} disabled={isLoading}>
                    {isLoading ? "Saving..." : "Save Changes"}
                  </Button>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}