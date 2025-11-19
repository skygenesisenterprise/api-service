"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { User, Mail, Phone, Calendar, Shield, Globe, Bell, Palette, X } from "lucide-react";

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ProfileModal({ isOpen, onClose }: ProfileModalProps) {
  const [user, setUser] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    timezone: "",
    language: ""
  });

  useEffect(() => {
    if (isOpen) {
      // Load user data from localStorage
      const userData = localStorage.getItem("user");
      
      if (userData) {
        const parsedUser = JSON.parse(userData);
        setUser(parsedUser);
        
        // Set form data from user profile
        if (parsedUser.profile) {
          setFormData({
            firstName: parsedUser.profile.firstName || "",
            lastName: parsedUser.profile.lastName || "",
            email: parsedUser.primaryEmail || "",
            phone: parsedUser.phoneNumber || "",
            timezone: parsedUser.profile.timezone || "UTC",
            language: parsedUser.profile.language || "en"
          });
        }
      }
    }
  }, [isOpen]);

  const handleSave = async () => {
    setIsLoading(true);
    try {
      // TODO: Update user profile via API
      console.log("Saving profile:", formData);
      
      // For now, just update localStorage
      if (user) {
        const updatedUser = {
          ...user,
          profile: {
            ...user.profile,
            firstName: formData.firstName,
            lastName: formData.lastName,
            timezone: formData.timezone,
            language: formData.language
          }
        };
        localStorage.setItem("user", JSON.stringify(updatedUser));
        setUser(updatedUser);
      }
      
      setIsEditing(false);
    } catch (error) {
      console.error("Failed to save profile:", error);
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
      <div className="relative z-10 w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <Card className="bg-white shadow-2xl">
          {/* Header */}
          <CardHeader className="flex items-center justify-between pb-4">
            <div>
              <CardTitle className="flex items-center gap-2 text-xl">
                <User className="h-5 w-5" />
                Profile
              </CardTitle>
              <CardDescription>Manage your account information</CardDescription>
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
                {/* Profile Header */}
                <div className="flex items-center gap-4 p-4 bg-gray-50 rounded-lg">
                  <Avatar className="h-16 w-16">
                    <AvatarImage src={user.profile?.avatar} />
                    <AvatarFallback className="text-lg bg-gradient-to-br from-blue-500 to-purple-600 text-white">
                      {user.profile?.firstName?.[0] || user.primaryEmail?.[0]?.toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1">
                    <h3 className="text-lg font-semibold text-gray-900">
                      {user.profile?.firstName && user.profile?.lastName 
                        ? `${user.profile.firstName} ${user.profile.lastName}`
                        : user.primaryEmail}
                    </h3>
                    <p className="text-gray-600">{user.primaryEmail}</p>
                    <p className="text-sm text-gray-400">Global ID: {user.globalId}</p>
                  </div>
                  <Button
                    variant={isEditing ? "default" : "outline"}
                    onClick={() => isEditing ? handleSave() : setIsEditing(true)}
                    disabled={isLoading}
                  >
                    {isLoading ? "Saving..." : isEditing ? "Save Changes" : "Edit Profile"}
                  </Button>
                </div>

                <Separator />

                {/* Form Fields */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="firstName">First Name</Label>
                    <Input
                      id="firstName"
                      value={formData.firstName}
                      onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
                      disabled={!isEditing}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="lastName">Last Name</Label>
                    <Input
                      id="lastName"
                      value={formData.lastName}
                      onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
                      disabled={!isEditing}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="email" className="flex items-center gap-2">
                    <Mail className="h-4 w-4" />
                    Email Address
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    disabled={!isEditing}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="phone" className="flex items-center gap-2">
                    <Phone className="h-4 w-4" />
                    Phone Number
                  </Label>
                  <Input
                    id="phone"
                    type="tel"
                    value={formData.phone}
                    onChange={(e) => setFormData({ ...formData, phone: e.target.value })}
                    disabled={!isEditing}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="timezone" className="flex items-center gap-2">
                      <Globe className="h-4 w-4" />
                      Timezone
                    </Label>
                    <select
                      id="timezone"
                      value={formData.timezone}
                      onChange={(e) => setFormData({ ...formData, timezone: e.target.value })}
                      disabled={!isEditing}
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
                  <div className="space-y-2">
                    <Label htmlFor="language" className="flex items-center gap-2">
                      <Globe className="h-4 w-4" />
                      Language
                    </Label>
                    <select
                      id="language"
                      value={formData.language}
                      onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                      disabled={!isEditing}
                      className="w-full p-2 border border-gray-300 rounded-md"
                    >
                      <option value="en">English</option>
                      <option value="fr">Français</option>
                      <option value="es">Español</option>
                      <option value="de">Deutsch</option>
                      <option value="ja">日本語</option>
                    </select>
                  </div>
                </div>

                <Separator />

                {/* Account Status */}
                <div className="p-4 bg-gray-50 rounded-lg">
                  <h4 className="font-medium text-gray-900 mb-3 flex items-center gap-2">
                    <Shield className="h-4 w-4" />
                    Account Status
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex items-center gap-2">
                      <div className={`h-3 w-3 rounded-full ${user.isVerified ? 'bg-green-500' : 'bg-yellow-500'}`}></div>
                      <span className="text-sm">
                        {user.isVerified ? 'Verified Account' : 'Email Not Verified'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={`h-3 w-3 rounded-full ${user.status === 'active' ? 'bg-green-500' : 'bg-red-500'}`}></div>
                      <span className="text-sm capitalize">{user.status} Account</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-gray-500">
                      <Calendar className="h-4 w-4" />
                      Member since {new Date(user.createdAt).toLocaleDateString()}
                    </div>
                    {user.lastLoginAt && (
                      <div className="flex items-center gap-2 text-sm text-gray-500">
                        <Calendar className="h-4 w-4" />
                        Last login {new Date(user.lastLoginAt).toLocaleDateString()}
                      </div>
                    )}
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