import { 
  Settings, 
  Building2, 
  Users, 
  Shield, 
  Key,
  FileText,
  CreditCard,
  AlertTriangle,
  Globe,
  Server,
  Lock,
  Plus,
  Download,
  Clock,
  KeyRound,
  Fingerprint,
  ShieldCheck,
  ShieldAlert,
  Crown,
  Activity,
  Database,
  Wifi
} from "lucide-react";
import type { NavigationCategory } from "../types/settings";

export const navigationCategories: NavigationCategory[] = [
  {
    id: "general",
    title: "General",
    icon: Settings,
    items: [
      { id: "organization", label: "Organization", icon: Building2 },
      { id: "workspace", label: "Workspace", icon: Server },
      { id: "branding", label: "Branding", icon: Globe }
    ]
  },
  {
    id: "access",
    title: "Access & Permissions",
    icon: Users,
    items: [
      { id: "members", label: "Members", icon: Users },
      { id: "roles", label: "Roles", icon: Shield },
      { id: "api-policy", label: "API Access Policy", icon: Key }
    ]
  },
  {
    id: "auth",
    title: "Authentication",
    icon: Lock,
    items: [
      { id: "password-policy", label: "Password Policy", icon: KeyRound },
      { id: "mfa", label: "2FA / MFA", icon: Fingerprint },
      { id: "sso", label: "SSO Providers", icon: ShieldCheck },
      { id: "session", label: "Session Lifetime", icon: Clock }
    ]
  },
  {
    id: "api-keys",
    title: "API Keys",
    icon: Key,
    items: [
      { id: "keys-list", label: "API Keys", icon: Key },
      { id: "create-key", label: "Create New Key", icon: Plus }
    ]
  },
  {
    id: "audit",
    title: "Audit Logs",
    icon: FileText,
    items: [
      { id: "logs", label: "Activity Logs", icon: FileText },
      { id: "export", label: "Export Logs", icon: Download }
    ]
  },
  {
    id: "billing",
    title: "Billing",
    icon: CreditCard,
    items: [
      { id: "plan", label: "Plan", icon: Crown },
      { id: "usage", label: "Usage", icon: Activity },
      { id: "invoices", label: "Invoice History", icon: FileText }
    ]
  },
  {
    id: "advanced",
    title: "Advanced",
    icon: AlertTriangle,
    items: [
      { id: "webhooks", label: "Webhooks", icon: Wifi },
      { id: "retention", label: "Data Retention", icon: Database },
      { id: "encryption", label: "Encryption", icon: ShieldAlert },
      { id: "danger-zone", label: "Danger Zone", icon: AlertTriangle }
    ]
  }
];