"use client";

import { ReactNode } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/app/components/ui/card";
import { cn } from "@/app/lib/utils";

interface WidgetCardProps {
  title: string;
  children: ReactNode;
  className?: string;
  headerAction?: ReactNode;
}

export function WidgetCard({ title, children, className, headerAction }: WidgetCardProps) {
  return (
    <Card className={cn("h-full bg-gray-900/95 border-gray-800", className)}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-gray-400">
          {title}
        </CardTitle>
        {headerAction}
      </CardHeader>
      <CardContent className="pt-0">
        {children}
      </CardContent>
    </Card>
  );
}