"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Shield, Lock, Smartphone, Key, AlertTriangle, CheckCircle, Clock } from "lucide-react";

export default function SecurityPage() {
  const [user, setUser] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [sessions, setSessions] = useState([
    {
      id: '1',
      device: 'Chrome on Windows',
      location: 'Paris, France',
      ip: '192.168.1.1',
      lastActive: new Date(),
      isCurrent: true
    },
    {
      id: '2',
      device: 'Safari on iPhone',
      location: 'Lyon, France', 
      ip: '192.168.1.2',
      lastActive: new Date(Date.now() - 2 * 60 * 60 * 1000),
      isCurrent: false
    }
  ]);

  useEffect(() => {
    // Load user data from localStorage
    const userData = localStorage.getItem("user");
    
    if (userData) {
      const parsedUser = JSON.parse(userData);
      setUser(parsedUser);
    }
  }, []);

  const handleRevokeSession = async (sessionId: string) => {
    try {
      // TODO: Revoke session via API
      setSessions(sessions.filter(s => s.id !== sessionId));
    } catch (error) {
      console.error("Failed to revoke session:", error);
    }
  };

  const handleRevokeAllSessions = async () => {
    try {
      // TODO: Revoke all sessions via API
      setSessions(sessions.filter(s => s.isCurrent));
    } catch (error) {
      console.error("Failed to revoke all sessions:", error);
    }
  };

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-8 px-4 max-w-4xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Security</h1>
        <p className="text-gray-600 mt-2">Manage your account security and authentication</p>
      </div>

      <div className="grid gap-6">
        {/* Security Overview */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Security Overview
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center gap-3 p-4 bg-green-50 rounded-lg">
                <CheckCircle className="h-8 w-8 text-green-600" />
                <div>
                  <p className="font-semibold text-green-900">2FA Enabled</p>
                  <p className="text-sm text-green-700">Extra protection active</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3 p-4 bg-blue-50 rounded-lg">
                <Lock className="h-8 w-8 text-blue-600" />
                <div>
                  <p className="font-semibold text-blue-900">Strong Password</p>
                  <p className="text-sm text-blue-700">Last changed 30 days ago</p>
                </div>
              </div>
              
              <div className="flex items-center gap-3 p-4 bg-yellow-50 rounded-lg">
                <Smartphone className="h-8 w-8 text-yellow-600" />
                <div>
                  <p className="font-semibold text-yellow-900">2 Sessions</p>
                  <p className="text-sm text-yellow-700">1 active, 1 inactive</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Active Sessions */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  Active Sessions
                </CardTitle>
                <CardDescription>Manage your active login sessions</CardDescription>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                onClick={handleRevokeAllSessions}
              >
                Revoke All Others
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {sessions.map((session) => (
              <div key={session.id} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                <div className="flex items-center gap-3">
                  <Smartphone className="h-5 w-5 text-gray-400" />
                  <div>
                    <p className="font-medium text-gray-900">
                      {session.device}
                      {session.isCurrent && (
                        <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                          Current
                        </span>
                      )}
                    </p>
                    <p className="text-sm text-gray-500">{session.location}</p>
                    <p className="text-xs text-gray-400">IP: {session.ip}</p>
                  </div>
                </div>
                <div className="text-right">
                  <p className="text-sm text-gray-500">
                    Last active: {session.lastActive.toLocaleString()}
                  </p>
                  {!session.isCurrent && (
                    <Button 
                      variant="outline" 
                      size="sm" 
                      className="mt-1"
                      onClick={() => handleRevokeSession(session.id)}
                    >
                      Revoke
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Password */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5" />
              Password
            </CardTitle>
            <CardDescription>Change your account password</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="current-password">Current Password</Label>
                <Input
                  id="current-password"
                  type="password"
                  placeholder="Enter current password"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="new-password">New Password</Label>
                <Input
                  id="new-password"
                  type="password"
                  placeholder="Enter new password"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm New Password</Label>
              <Input
                id="confirm-password"
                type="password"
                placeholder="Confirm new password"
              />
            </div>
            <Button>Update Password</Button>
          </CardContent>
        </Card>

        {/* Two-Factor Authentication */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Two-Factor Authentication
            </CardTitle>
            <CardDescription>Add an extra layer of security to your account</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 bg-green-100 rounded-full flex items-center justify-center">
                  <CheckCircle className="h-5 w-5 text-green-600" />
                </div>
                <div>
                  <p className="font-medium text-gray-900">Authenticator App</p>
                  <p className="text-sm text-gray-500">Using Google Authenticator</p>
                </div>
              </div>
              <Button variant="outline">Manage</Button>
            </div>
            
            <div className="space-y-3">
              <Button variant="outline" className="w-full justify-start">
                <Smartphone className="h-4 w-4 mr-2" />
                Add SMS Authentication
              </Button>
              
              <Button variant="outline" className="w-full justify-start">
                <Key className="h-4 w-4 mr-2" />
                Add Backup Codes
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Security Alerts */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Security Alerts
            </CardTitle>
            <CardDescription>Configure security notifications</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">New login alert</p>
                  <p className="text-sm text-gray-500">Get notified when someone logs into your account</p>
                </div>
                <Button variant="outline" size="sm">Configure</Button>
              </div>
              
              <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">Password change alert</p>
                  <p className="text-sm text-gray-500">Get notified when your password is changed</p>
                </div>
                <Button variant="outline" size="sm">Configure</Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}