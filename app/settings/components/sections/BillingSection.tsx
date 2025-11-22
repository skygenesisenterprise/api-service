"use client";

import { Crown, Activity, CreditCard, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

interface BillingSectionProps {
  activeSection: string;
}

export function BillingSection({ activeSection }: BillingSectionProps) {
  if (activeSection === "plan") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Current Plan</CardTitle>
            <CardDescription>Manage your subscription and billing</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="p-6 bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-2xl">
              <div className="flex items-center justify-between mb-4">
                <span className="text-sm font-medium text-gray-600">Current Plan</span>
                <Badge className="bg-gradient-to-r from-blue-600 to-purple-600 text-white text-sm px-4 py-2">
                  <Crown className="w-4 h-4 mr-2" />
                  Enterprise
                </Badge>
              </div>
              <div className="text-3xl font-bold text-gray-900 mb-2">$499/month</div>
              <div className="text-sm text-gray-600">
                Renews on December 1, 2024
              </div>
              <div className="flex items-center gap-2 pt-4">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-sm font-medium">Active</span>
              </div>
            </div>

            <div className="flex gap-4">
              <Button variant="outline" className="flex items-center gap-2">
                <CreditCard className="w-4 h-4" />
                Update Payment Method
              </Button>
              <Button className="flex items-center gap-2">
                <Crown className="w-4 h-4" />
                Upgrade Plan
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (activeSection === "usage") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Usage Overview</CardTitle>
            <CardDescription>Monitor your resource consumption</CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">API Requests</span>
                  <span className="text-sm text-gray-600">2.4M / 10M</span>
                </div>
                <Progress value={24} className="h-2" />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Storage</span>
                  <span className="text-sm text-gray-600">450GB / 1TB</span>
                </div>
                <Progress value={45} className="h-2" />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Bandwidth</span>
                  <span className="text-sm text-gray-600">8.2TB / 20TB</span>
                </div>
                <Progress value={41} className="h-2" />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">Compute Time</span>
                  <span className="text-sm text-gray-600">2,500h / 10,000h</span>
                </div>
                <Progress value={25} className="h-2" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (activeSection === "invoices") {
    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Invoice History</CardTitle>
            <CardDescription>Download your billing statements and receipts</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Invoice Number</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Amount</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow>
                  <TableCell className="font-medium">INV-2024-001</TableCell>
                  <TableCell>November 1, 2024</TableCell>
                  <TableCell className="font-medium">$499</TableCell>
                  <TableCell>
                    <Badge className="bg-emerald-100 text-emerald-800">Paid</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="outline" size="sm">
                      <Download className="w-4 h-4" />
                    </Button>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium">INV-2024-002</TableCell>
                  <TableCell>October 1, 2024</TableCell>
                  <TableCell className="font-medium">$499</TableCell>
                  <TableCell>
                    <Badge className="bg-emerald-100 text-emerald-800">Paid</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="outline" size="sm">
                      <Download className="w-4 h-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    );
  }

  return null;
}