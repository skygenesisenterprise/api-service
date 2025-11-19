"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Activity, Clock, Shield, AlertTriangle, CheckCircle, Search, Filter } from "lucide-react";

export default function ActivityPage() {
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
    // Load user data from localStorage
    const userData = localStorage.getItem("user");
    
    if (userData) {
      const parsedUser = JSON.parse(userData);
      setUser(parsedUser);
    }
  }, []);

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
        <h1 className="text-3xl font-bold text-gray-900">Activity</h1>
        <p className="text-gray-600 mt-2">Monitor your recent account activity and security events</p>
      </div>

      <div className="grid gap-6">
        {/* Activity Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 bg-blue-100 rounded-full flex items-center justify-center">
                  <Activity className="h-5 w-5 text-blue-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-900">24</p>
                  <p className="text-sm text-gray-500">Total Activities</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 bg-green-100 rounded-full flex items-center justify-center">
                  <CheckCircle className="h-5 w-5 text-green-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-900">18</p>
                  <p className="text-sm text-gray-500">Successful</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 bg-yellow-100 rounded-full flex items-center justify-center">
                  <AlertTriangle className="h-5 w-5 text-yellow-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-900">3</p>
                  <p className="text-sm text-gray-500">Warnings</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 bg-red-100 rounded-full flex items-center justify-center">
                  <Shield className="h-5 w-5 text-red-600" />
                </div>
                <div>
                  <p className="text-2xl font-bold text-gray-900">3</p>
                  <p className="text-sm text-gray-500">Security Events</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Search and Filter */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Search & Filter
            </CardTitle>
          </CardHeader>
          <CardContent>
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
          </CardContent>
        </Card>

        {/* Activity List */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Clock className="h-5 w-5" />
              Recent Activity
            </CardTitle>
            <CardDescription>Your account activity from the last 30 days</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {filteredActivities.map((activity) => (
                <div key={activity.id} className="flex items-start gap-4 p-4 border border-gray-200 rounded-lg hover:bg-gray-50">
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
          </CardContent>
        </Card>

        {/* Export Options */}
        <Card>
          <CardHeader>
            <CardTitle>Export Activity</CardTitle>
            <CardDescription>Download your activity history for your records</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-3">
              <Button variant="outline" className="flex items-center gap-2">
                <Filter className="h-4 w-4" />
                Export as CSV
              </Button>
              <Button variant="outline" className="flex items-center gap-2">
                <Filter className="h-4 w-4" />
                Export as JSON
              </Button>
              <Button variant="outline" className="flex items-center gap-2">
                <Filter className="h-4 w-4" />
                Export as PDF
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}