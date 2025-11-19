"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Activity, Clock, Shield, AlertTriangle, CheckCircle, Search, Filter, X, Download } from "lucide-react";

interface ActivityModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ActivityModal({ isOpen, onClose }: ActivityModalProps) {
  const [user, setUser] = useState<any>(null);
  const [activities, setActivities] = useState([
    {
      id: '1',
      type: 'login',
      description: 'Successfully logged in from Chrome on Windows',
      details: 'IP: 192.168.1.1, Location: Paris, France',
      timestamp: new Date(),
      status: 'success'
    },
    {
      id: '2', 
      type: 'api_key_created',
      description: 'Created new API key',
      details: 'Key: sk_test_...xyz, Permissions: read, write',
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
      status: 'success'
    },
    {
      id: '3',
      type: 'security_alert',
      description: 'Failed login attempt detected',
      details: 'IP: 185.220.101.182, Location: Unknown, Multiple attempts',
      timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000),
      status: 'warning'
    },
    {
      id: '4',
      type: 'profile_updated',
      description: 'Profile information updated',
      details: 'Changed: First name, Language',
      timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000),
      status: 'success'
    },
    {
      id: '5',
      type: 'password_changed',
      description: 'Password successfully changed',
      details: 'Method: Email verification, IP: 192.168.1.1',
      timestamp: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
      status: 'success'
    }
  ]);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");

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

  const getActivityIcon = (type: string, status: string) => {
    switch (type) {
      case 'login':
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case 'api_key_created':
        return <Shield className="h-4 w-4 text-blue-600" />;
      case 'security_alert':
        return <AlertTriangle className="h-4 w-4 text-yellow-600" />;
      case 'profile_updated':
        return <Activity className="h-4 w-4 text-purple-600" />;
      case 'password_changed':
        return <Shield className="h-4 w-4 text-red-600" />;
      default:
        return <Activity className="h-4 w-4 text-gray-600" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'warning':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'error':
        return 'bg-red-100 text-red-800 border-red-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const filteredActivities = activities.filter(activity => {
    const matchesSearch = activity.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         activity.details.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = filterType === "all" || activity.type === filterType;
    return matchesSearch && matchesFilter;
  });

  const handleExport = (format: 'csv' | 'json' | 'pdf') => {
    // TODO: Implement export functionality
    console.log(`Exporting activities as ${format}`);
    
    // For now, just create a simple CSV
    if (format === 'csv') {
      const csv = [
        ['Timestamp', 'Type', 'Description', 'Status', 'Details'],
        ...activities.map(a => [
          a.timestamp.toISOString(),
          a.type,
          a.description,
          a.status,
          a.details
        ])
      ].map(row => row.join(',')).join('\n');
      
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `activity-${new Date().toISOString().split('T')[0]}.csv`;
      a.click();
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
      <div className="relative z-10 w-full max-w-5xl mx-4 max-h-[90vh] overflow-y-auto">
        <Card className="bg-white shadow-2xl">
          {/* Header */}
          <CardHeader className="flex items-center justify-between pb-4">
            <div>
              <CardTitle className="flex items-center gap-2 text-xl">
                <Activity className="h-5 w-5" />
                Activity
              </CardTitle>
              <CardDescription>Monitor your recent account activity and security events</CardDescription>
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
                {/* Activity Stats */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <div className="text-2xl font-bold text-blue-900">24</div>
                    <div className="text-sm text-blue-700">Total Activities</div>
                  </div>
                  
                  <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                    <div className="text-2xl font-bold text-green-900">18</div>
                    <div className="text-sm text-green-700">Successful</div>
                  </div>
                  
                  <div className="p-4 bg-yellow-50 rounded-lg border border-yellow-200">
                    <div className="text-2xl font-bold text-yellow-900">3</div>
                    <div className="text-sm text-yellow-700">Warnings</div>
                  </div>
                  
                  <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                    <div className="text-2xl font-bold text-red-900">3</div>
                    <div className="text-sm text-red-700">Security Events</div>
                  </div>
                </div>

                {/* Search and Filter */}
                <div className="space-y-4">
                  <div className="flex flex-col md:flex-row gap-4">
                    <div className="flex-1">
                      <Input
                        placeholder="Search activities..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full"
                      />
                    </div>
                    <select
                      value={filterType}
                      onChange={(e) => setFilterType(e.target.value)}
                      className="px-3 py-2 border border-gray-300 rounded-md bg-white"
                    >
                      <option value="all">All Activities</option>
                      <option value="login">Logins</option>
                      <option value="api_key_created">API Keys</option>
                      <option value="security_alert">Security</option>
                      <option value="profile_updated">Profile Changes</option>
                      <option value="password_changed">Password Changes</option>
                    </select>
                  </div>
                </div>
                </div>

                {/* Activity List */}
                <div className="space-y-4">
                  <div className="max-h-96 overflow-y-auto border border-gray-200 rounded-lg">
                    {filteredActivities.map((activity) => (
                      <div key={activity.id} className="flex items-start gap-4 p-4 hover:bg-gray-50 border-b border-gray-100 last:border-b-0">
                        <div className="mt-1">
                          {getActivityIcon(activity.type, activity.status)}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <p className="font-medium text-gray-900">{activity.description}</p>
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${getStatusColor(activity.status)}`}>
                              {activity.status}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 mb-2">{activity.details}</p>
                          <p className="text-xs text-gray-400">
                            {activity.timestamp.toLocaleString()}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Export Options */}
                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-gray-900">Export Activity</h3>
                  <p className="text-sm text-gray-600 mb-4">Download your activity history for your records</p>
                  <div className="flex flex-col sm:flex-row gap-3">
                    <Button 
                      variant="outline" 
                      className="flex items-center gap-2"
                      onClick={() => handleExport('csv')}
                    >
                      <Download className="h-4 w-4" />
                      Export as CSV
                    </Button>
                    <Button 
                      variant="outline" 
                      className="flex items-center gap-2"
                      onClick={() => handleExport('json')}
                    >
                      <Download className="h-4 w-4" />
                      Export as JSON
                    </Button>
                    <Button 
                      variant="outline" 
                      className="flex items-center gap-2"
                      onClick={() => handleExport('pdf')}
                    >
                      <Download className="h-4 w-4" />
                      Export as PDF
                    </Button>
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