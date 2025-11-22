"use client";

import { Save, Lock, KeyRound, Fingerprint, ShieldCheck, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

interface AuthSectionProps {
  activeSection: string;
}

export function AuthSection({ activeSection }: AuthSectionProps) {
  if (activeSection === "password-policy") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Password Policy</CardTitle>
            <CardDescription>Configure password requirements for your organization</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Minimum Length</p>
                  <p className="text-sm text-gray-600">Require passwords to be at least 12 characters</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Require Uppercase</p>
                  <p className="text-sm text-gray-600">Require at least one uppercase letter</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Require Numbers</p>
                  <p className="text-sm text-gray-600">Require at least one number</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Require Symbols</p>
                  <p className="text-sm text-gray-600">Require at least one special character</p>
                </div>
                <Switch defaultChecked />
              </div>
            </div>

            <div className="flex justify-end">
              <Button className="flex items-center gap-2">
                <Save className="w-4 h-4" />
                Save Policy
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (activeSection === "mfa") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Two-Factor Authentication</CardTitle>
            <CardDescription>Configure 2FA requirements for your organization</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Enforce 2FA for all users</p>
                  <p className="text-sm text-gray-600">Require two-factor authentication for all team members</p>
                </div>
                <Switch defaultChecked />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Allow SMS 2FA</p>
                  <p className="text-sm text-gray-600">Allow users to use SMS for two-factor authentication</p>
                </div>
                <Switch />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Require hardware keys</p>
                  <p className="text-sm text-gray-600">Require hardware security keys for admin users</p>
                </div>
                <Switch />
              </div>
            </div>

            <div className="flex justify-end">
              <Button className="flex items-center gap-2">
                <Save className="w-4 h-4" />
                Save Settings
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (activeSection === "sso") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Single Sign-On (SSO)</CardTitle>
            <CardDescription>Configure SSO providers for your organization</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-blue-100 rounded-lg flex items-center justify-center">
                      <ShieldCheck className="w-4 h-4 text-blue-600" />
                    </div>
                    <div>
                      <p className="font-medium">SAML 2.0</p>
                      <p className="text-sm text-gray-600">Enterprise SSO via SAML</p>
                    </div>
                  </div>
                  <Switch />
                </div>
                <Button variant="outline" size="sm">Configure SAML</Button>
              </div>

              <div className="border rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-green-100 rounded-lg flex items-center justify-center">
                      <KeyRound className="w-4 h-4 text-green-600" />
                    </div>
                    <div>
                      <p className="font-medium">OpenID Connect</p>
                      <p className="text-sm text-gray-600">OAuth 2.0 / OIDC integration</p>
                    </div>
                  </div>
                  <Switch />
                </div>
                <Button variant="outline" size="sm">Configure OIDC</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (activeSection === "session") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Session Management</CardTitle>
            <CardDescription>Configure session lifetime and security settings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label>Session Timeout (hours)</Label>
                <Select defaultValue="24">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">1 hour</SelectItem>
                    <SelectItem value="8">8 hours</SelectItem>
                    <SelectItem value="24">24 hours</SelectItem>
                    <SelectItem value="168">7 days</SelectItem>
                    <SelectItem value="720">30 days</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Require re-authentication for sensitive actions</p>
                  <p className="text-sm text-gray-600">Ask users to re-authenticate for critical operations</p>
                </div>
                <Switch defaultChecked />
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <p className="font-medium">Concurrent sessions</p>
                  <p className="text-sm text-gray-600">Allow users to have multiple active sessions</p>
                </div>
                <Switch />
              </div>
            </div>

            <div className="flex justify-end">
              <Button className="flex items-center gap-2">
                <Save className="w-4 h-4" />
                Save Settings
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return null;
}