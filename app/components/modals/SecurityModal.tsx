"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Shield, Lock, Smartphone, Key, AlertTriangle, CheckCircle, Clock, X } from "lucide-react";

interface SecurityModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SecurityModal({ isOpen, onClose }: SecurityModalProps) {
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
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });

  useEffect(() => {
    if (isOpen) {
      // Load user data from localStorage
      const userData = localStorage.getItem("user");
      
      if (userData) {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
      }
    }
  }, [isOpen]);

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

  const handlePasswordChange = async () => {
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    setIsLoading(true);
    try {
      // TODO: Change password via API
      console.log("Changing password:", passwordData);
      
      // Clear form
      setPasswordData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      });
    } catch (error) {
      console.error("Failed to change password:", error);
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
                <Shield className="h-5 w-5" />
                Security
              </CardTitle>
              <CardDescription>Manage your account security and authentication</CardDescription>
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
                {/* Security Overview */}
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

                <Separator />

                {/* Active Sessions */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                      <Clock className="h-5 w-5" />
                      Active Sessions
                    </h3>
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={handleRevokeAllSessions}
                    >
                      Revoke All Others
                    </Button>
                  </div>
                  
                  <div className="space-y-4">
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
                  </div>
                </div>

                <Separator />

                {/* Password */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Password
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="current-password">Current Password</Label>
                      <Input
                        id="current-password"
                        type="password"
                        placeholder="Enter current password"
                        value={passwordData.currentPassword}
                        onChange={(e) => setPasswordData({ ...passwordData, currentPassword: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="new-password">New Password</Label>
                      <Input
                        id="new-password"
                        type="password"
                        placeholder="Enter new password"
                        value={passwordData.newPassword}
                        onChange={(e) => setPasswordData({ ...passwordData, newPassword: e.target.value })}
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="confirm-password">Confirm New Password</Label>
                    <Input
                      id="confirm-password"
                      type="password"
                      placeholder="Confirm new password"
                      value={passwordData.confirmPassword}
                      onChange={(e) => setPasswordData({ ...passwordData, confirmPassword: e.target.value })}
                    />
                  </div>
                  <Button onClick={handlePasswordChange} disabled={isLoading}>
                    {isLoading ? "Updating..." : "Update Password"}
                  </Button>
                </div>

                <Separator />

                {/* Two-Factor Authentication */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <Key className="h-5 w-5" />
                    Two-Factor Authentication
                  </h3>
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
                </div>

                <Separator />

                {/* Security Alerts */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5" />
                    Security Alerts
                  </h3>
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