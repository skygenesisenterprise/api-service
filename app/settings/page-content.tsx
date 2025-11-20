"use client";

import { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence, useAnimation } from "framer-motion";
import { 
  Settings, 
  Building2, 
  Users, 
  Shield, 
  CreditCard, 
  FileText,
  Plus,
  Search,
  Filter,
  MoreHorizontal,
  Mail,
  UserPlus,
  Trash2,
  Edit,
  Check,
  X,
  Upload,
  Globe,
  Server,
  Key,
  Lock,
  Clock,
  Download,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  RefreshCw,
  Eye,
  EyeOff,
  Copy,
  Zap,
  Activity,
  BarChart3,
  TrendingUp,
  TrendingDown,
  UserCheck,
  UserX,
  ShieldCheck,
  ShieldAlert,
  Database,
  Wifi,
  WifiOff,
  Cpu,
  HardDrive,
  Calendar,
  Bell,
  BellRing,
  Save,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertCircle as AlertCircleIcon,
  Info,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  ArrowUpDown,
  Maximize2,
  Minimize2,
  RotateCw as RotateIcon,
  Sun,
  Moon,
  Monitor,
  Smartphone,
  Tablet,
  Globe2,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  UserCog,
  Settings2,
  LogOut,
  UserRound,
  Crown,
  Star,
  ZapOff,
  Cloud,
  CloudRain,
  CloudSnow,
  CloudDrizzle,
  CloudLightning,
  CloudCog,
  CloudDownload,
  CloudUpload,
  ServerCog,
  CpuChip,
  MemoryStick,
  HardDrive2,
  Disc,
  Usb,
  Bluetooth,
  WifiOff as WifiOffIcon,
  Router,
  Network,
  Globe3,
  MapPin,
  Navigation,
  Compass,
  Radar,
  ScanLine,
  Target,
  Crosshair,
  MousePointer2,
  Touchpad,
  Keyboard,
  MonitorSpeaker,
  Volume2,
  Mic2,
  Video,
  Camera,
  Image,
  FileImage,
  FileVideo,
  FileAudio,
  FileText as FileTextIcon,
  FileCode,
  FileArchive,
  FileSpreadsheet,
  FilePlus,
  FileDown,
  FileUp,
  FileSearch,
  FileX,
  Folder,
  FolderOpen,
  FolderPlus,
  FolderDown,
  FolderUp,
  FolderTree,
  Archive,
  ArchiveRestore,
  Package,
  PackageOpen,
  PackagePlus,
  PackageX,
  Truck,
  Plane,
  Car,
  Train,
  Ship,
  Bike,
  Footprints,
  Zap as ZapIcon,
  Battery,
  BatteryCharging,
  BatteryLow,
  BatteryFull,
  BatteryMedium,
  BatteryHigh,
  BatteryCharging2,
  Power,
  PowerOff,
  Plug,
  PlugZap,
  Unplug,
  Lightning,
  Bolt,
  Sparkles,
  Sparkle,
  StarHalf,
  StarOff,
  Heart,
  HeartHandshake,
  ThumbsUp,
  ThumbsDown,
  MessageSquare,
  MessageCircle,
  MessageCirclePlus,
  MessageCircleMinus,
  MessageSquarePlus,
  MessageSquareMinus,
  Send,
  SendHorizontal,
  SendToBack,
  Reply,
  ReplyAll,
  Forward,
  Share,
  Share2,
  Link,
  Link2,
  Link2Off,
  Unlink,
  Paperclip,
  PaperclipOff,
  Scissors,
  Type,
  TypeOutline,
  Highlighter,
  Underline,
  Strikethrough,
  Italic,
  Bold,
  Code,
  Code2,
  Terminal,
  TerminalSquare,
  Command,
  Shell,
  Cpu as CpuIcon,
  MemoryStick as MemoryStickIcon,
  HardDrive as HardDriveIcon,
  Disc as DiscIcon,
  Usb as UsbIcon,
  Bluetooth as BluetoothIcon,
  Wifi as WifiIcon,
  Router as RouterIcon,
  Network as NetworkIcon,
  Globe as GlobeIcon,
  MapPin as MapPinIcon,
  Navigation as NavigationIcon,
  Compass as CompassIcon,
  Radar as RadarIcon,
  ScanLine as ScanLineIcon,
  Target as TargetIcon,
  Crosshair as CrosshairIcon,
  MousePointer2 as MousePointer2Icon,
  Touchpad as TouchpadIcon,
  Keyboard as KeyboardIcon,
  MonitorSpeaker as MonitorSpeakerIcon,
  Volume2 as Volume2Icon,
  Mic2 as Mic2Icon,
  Video as VideoIcon,
  Camera as CameraIcon,
  Image as ImageIcon,
  FileImage as FileImageIcon,
  FileVideo as FileVideoIcon,
  FileAudio as FileAudioIcon,
  FileText as FileTextIcon2,
  FileCode as FileCodeIcon,
  FileArchive as FileArchiveIcon,
  FileSpreadsheet as FileSpreadsheetIcon,
  FilePlus as FilePlusIcon,
  FileDown as FileDownIcon,
  FileUp as FileUpIcon,
  FileSearch as FileSearchIcon,
  FileX as FileXIcon,
  Folder as FolderIcon,
  FolderOpen as FolderOpenIcon,
  FolderPlus as FolderPlusIcon,
  FolderDown as FolderDownIcon,
  FolderUp as FolderUpIcon,
  FolderTree as FolderTreeIcon,
  Archive as ArchiveIcon,
  ArchiveRestore as ArchiveRestoreIcon,
  Package as PackageIcon,
  PackageOpen as PackageOpenIcon,
  PackagePlus as PackagePlusIcon,
  PackageX as PackageXIcon,
  Truck as TruckIcon,
  Plane as PlaneIcon,
  Car as CarIcon,
  Train as TrainIcon,
  Ship as ShipIcon,
  Bike as BikeIcon,
  Footprints as FootprintsIcon,
  Zap as ZapIcon2,
  Battery as BatteryIcon,
  BatteryCharging as BatteryChargingIcon,
  BatteryLow as BatteryLowIcon,
  BatteryFull as BatteryFullIcon,
  BatteryMedium as BatteryMediumIcon,
  BatteryHigh as BatteryHighIcon,
  BatteryCharging2 as BatteryCharging2Icon,
  Power as PowerIcon,
  PowerOff as PowerOffIcon,
  Plug as PlugIcon,
  PlugZap as PlugZapIcon,
  Unplug as UnplugIcon,
  Lightning as LightningIcon,
  Bolt as BoltIcon,
  Sparkles as SparklesIcon,
  Sparkle as SparkleIcon,
  StarHalf as StarHalfIcon,
  StarOff as StarOffIcon,
  Heart as HeartIcon,
  HeartHandshake as HeartHandshakeIcon,
  ThumbsUp as ThumbsUpIcon,
  ThumbsDown as ThumbsDownIcon,
  MessageSquare as MessageSquareIcon,
  MessageCircle as MessageCircleIcon,
  MessageCirclePlus as MessageCirclePlusIcon,
  MessageCircleMinus as MessageCircleMinusIcon,
  MessageSquarePlus as MessageSquarePlusIcon,
  MessageSquareMinus as MessageSquareMinusIcon,
  Send as SendIcon,
  SendHorizontal as SendHorizontalIcon,
  SendToBack as SendToBackIcon,
  Reply as ReplyIcon,
  ReplyAll as ReplyAllIcon,
  Forward as ForwardIcon,
  Share as ShareIcon,
  Share2 as Share2Icon,
  Link as LinkIcon,
  Link2 as Link2Icon,
  Link2Off as Link2OffIcon,
  Unlink as UnlinkIcon,
  Paperclip as PaperclipIcon,
  PaperclipOff as PaperclipOffIcon,
  Scissors as ScissorsIcon,
  Type as TypeIcon,
  TypeOutline as TypeOutlineIcon,
  Highlighter as HighlighterIcon,
  Underline as UnderlineIcon,
  Strikethrough as StrikethroughIcon,
  Italic as ItalicIcon,
  Bold as BoldIcon,
  Code as CodeIcon,
  Code2 as Code2Icon,
  Terminal as TerminalIcon,
  TerminalSquare as TerminalSquareIcon,
  Command as CommandIcon,
  Shell as ShellIcon,
  Cpu as CpuIcon2,
  MemoryStick as MemoryStickIcon2,
  HardDrive as HardDriveIcon2,
  Disc as DiscIcon2,
  Usb as UsbIcon2,
  Bluetooth as BluetoothIcon2,
  Wifi as WifiIcon2,
  Router as RouterIcon2,
  Network as NetworkIcon2,
  Globe as GlobeIcon2,
  MapPin as MapPinIcon2,
  Navigation as NavigationIcon2,
  Compass as CompassIcon2,
  Radar as RadarIcon2,
  ScanLine as ScanLineIcon2,
  Target as TargetIcon2,
  Crosshair as CrosshairIcon2,
  MousePointer2 as MousePointer2Icon2,
  Touchpad as TouchpadIcon2,
  Keyboard as KeyboardIcon2,
  MonitorSpeaker as MonitorSpeakerIcon2,
  Volume2 as Volume2Icon2,
  Mic2 as Mic2Icon2,
  Video as VideoIcon2,
  Camera as CameraIcon2,
  Image as ImageIcon2,
  FileImage as FileImageIcon2,
  FileVideo as FileVideoIcon2,
  FileAudio as FileAudioIcon2,
  FileText as FileTextIcon3,
  FileCode as FileCodeIcon2,
  FileArchive as FileArchiveIcon2,
  FileSpreadsheet as FileSpreadsheetIcon2,
  FilePlus as FilePlusIcon2,
  FileDown as FileDownIcon2,
  FileUp as FileUpIcon2,
  FileSearch as FileSearchIcon2,
  FileX as FileXIcon2,
  Folder as FolderIcon2,
  FolderOpen as FolderOpenIcon2,
  FolderPlus as FolderPlusIcon2,
  FolderDown as FolderDownIcon2,
  FolderUp as FolderUpIcon2,
  FolderTree as FolderTreeIcon2,
  Archive as ArchiveIcon2,
  ArchiveRestore as ArchiveRestoreIcon2,
  Package as PackageIcon2,
  PackageOpen as PackageOpenIcon2,
  PackagePlus as PackagePlusIcon2,
  PackageX as PackageXIcon2,
  Truck as TruckIcon2,
  Plane as PlaneIcon2,
  Car as CarIcon2,
  Train as TrainIcon2,
  Ship as ShipIcon2,
  Bike as BikeIcon2,
  Footprints as FootprintsIcon2
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Progress } from "@/components/ui/progress";
import { Slider } from "@/components/ui/slider";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";

// Enhanced Types
interface Organization {
  id: string;
  name: string;
  description: string;
  domain: string;
  industry: string;
  logo?: string;
  website?: string;
  founded?: string;
  size: "startup" | "small" | "medium" | "large" | "enterprise";
  timezone: string;
  language: string;
}

interface Workspace {
  id: string;
  name: string;
  environment: "production" | "staging" | "development";
  region: "us" | "eu" | "asia" | "custom";
  plan: "free" | "pro" | "business" | "enterprise";
  apiQuota: number;
  storageQuota: number;
  bandwidthQuota: number;
}

interface Member {
  id: string;
  name: string;
  email: string;
  role: "owner" | "admin" | "developer" | "analyst" | "viewer" | "custom";
  status: "active" | "pending" | "inactive" | "suspended";
  lastActivity: Date;
  avatar?: string;
  department?: string;
  location?: string;
  permissions?: Permission[];
  mfaEnabled?: boolean;
  lastLogin?: Date;
}

interface Permission {
  id: string;
  name: string;
  description: string;
  category: "general" | "api" | "billing" | "security" | "admin";
  granted: boolean;
}

interface AuditLog {
  id: string;
  action: string;
  performedBy: string;
  timestamp: Date;
  ip: string;
  userAgent?: string;
  severity: "info" | "warning" | "error" | "critical";
  category: "auth" | "config" | "billing" | "security" | "api";
  details?: string;
}

interface SecuritySettings {
  enforce2FA: boolean;
  requireSSO: boolean;
  sessionTimeout: number;
  ipAllowlist: string[];
  allowedCountries: string[];
  blockSuspiciousIPs: boolean;
  rateLimiting: {
    enabled: boolean;
    requestsPerMinute: number;
    burstLimit: number;
  };
  passwordPolicy: {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSymbols: boolean;
    expiryDays: number;
  };
}

interface BillingInfo {
  plan: string;
  status: "active" | "trial" | "past_due" | "cancelled";
  renewalDate: Date;
  amount: number;
  currency: string;
  usage: {
    requests: {
      current: number;
      limit: number;
      period: string;
    };
    storage: {
      current: number;
      limit: number;
      unit: string;
    };
    bandwidth: {
      current: number;
      limit: number;
      unit: string;
    };
    compute: {
      current: number;
      limit: number;
      unit: string;
    };
  };
  paymentMethod: {
    type: "card" | "bank" | "crypto";
    last4?: string;
    brand?: string;
  };
  invoices: Invoice[];
}

interface Invoice {
  id: string;
  number: string;
  date: Date;
  amount: number;
  status: "paid" | "pending" | "failed";
  downloadUrl?: string;
}

// Enhanced Mock Data
const mockOrganization: Organization = {
  id: "org_123",
  name: "Sky Genesis Enterprise",
  description: "Leading provider of enterprise API solutions and infrastructure management platform",
  domain: "api.skygenesis.com",
  industry: "Technology",
  website: "https://skygenesis.com",
  founded: "2021",
  size: "enterprise",
  timezone: "UTC",
  language: "en"
};

const mockWorkspace: Workspace = {
  id: "ws_456",
  name: "Production Workspace",
  environment: "production",
  region: "us",
  plan: "enterprise",
  apiQuota: 10000000,
  storageQuota: 1024 * 1024 * 1024 * 1024, // 1TB
  bandwidthQuota: 1024 * 1024 * 1024 * 10 // 10TB
};

const mockMembers: Member[] = [
  {
    id: "1",
    name: "Alexandre Martin",
    email: "alex.martin@skygenesis.com",
    role: "owner",
    status: "active",
    lastActivity: new Date(Date.now() - 2 * 60 * 1000),
    avatar: "AM",
    department: "Engineering",
    location: "Paris, France",
    permissions: [
      { id: "1", name: "Full Access", description: "Complete control over organization", category: "admin", granted: true },
      { id: "2", name: "API Management", description: "Manage API keys and endpoints", category: "api", granted: true },
      { id: "3", name: "Billing Access", description: "View and manage billing", category: "billing", granted: true }
    ],
    mfaEnabled: true,
    lastLogin: new Date(Date.now() - 30 * 60 * 1000)
  },
  {
    id: "2", 
    name: "Sophie Dubois",
    email: "sophie.dubois@skygenesis.com",
    role: "admin",
    status: "active",
    lastActivity: new Date(Date.now() - 30 * 60 * 1000),
    avatar: "SD",
    department: "Product",
    location: "Lyon, France",
    permissions: [
      { id: "4", name: "User Management", description: "Manage team members", category: "admin", granted: true },
      { id: "5", name: "API Read", description: "Read-only API access", category: "api", granted: true }
    ],
    mfaEnabled: true,
    lastLogin: new Date(Date.now() - 2 * 60 * 60 * 1000)
  },
  {
    id: "3",
    name: "Thomas Bernard",
    email: "thomas.bernard@skygenesis.com",
    role: "developer",
    status: "active",
    lastActivity: new Date(Date.now() - 60 * 60 * 1000),
    avatar: "TB",
    department: "DevOps",
    location: "Marseille, France",
    permissions: [
      { id: "6", name: "Endpoint Access", description: "Access specific endpoints", category: "api", granted: true },
      { id: "7", name: "Logs View", description: "View system logs", category: "api", granted: true }
    ],
    mfaEnabled: false,
    lastLogin: new Date(Date.now() - 24 * 60 * 60 * 1000)
  },
  {
    id: "4",
    name: "Marie Laurent",
    email: "marie.laurent@skygenesis.com",
    role: "analyst",
    status: "pending",
    lastActivity: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
    avatar: "ML",
    department: "Data Science",
    location: "Lille, France",
    permissions: [
      { id: "8", name: "Analytics View", description: "View analytics and reports", category: "api", granted: true }
    ],
    mfaEnabled: false,
    lastLogin: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
  }
];

const mockAuditLogs: AuditLog[] = [
  {
    id: "1",
    action: "Updated organization settings",
    performedBy: "Alexandre Martin",
    timestamp: new Date(Date.now() - 30 * 60 * 1000),
    ip: "192.168.1.100",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    severity: "info",
    category: "config",
    details: "Updated organization name and industry"
  },
  {
    id: "2",
    action: "Changed member role",
    performedBy: "Alexandre Martin", 
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
    ip: "192.168.1.100",
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    severity: "warning",
    category: "admin",
    details: "Changed Sophie Dubois role from developer to admin"
  },
  {
    id: "3",
    action: "Enabled 2FA requirement",
    performedBy: "Sophie Dubois",
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000),
    ip: "10.0.0.45",
    userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    severity: "info",
    category: "security",
    details: "Enforced two-factor authentication for all users"
  },
  {
    id: "4",
    action: "API key regenerated",
    performedBy: "Thomas Bernard",
    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000),
    ip: "172.16.0.1",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    severity: "warning",
    category: "security",
    details: "Regenerated production API key due to security policy"
  }
];

const mockSecuritySettings: SecuritySettings = {
  enforce2FA: true,
  requireSSO: false,
  sessionTimeout: 24,
  ipAllowlist: ["192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16"],
  allowedCountries: ["FR", "US", "GB", "DE", "CA"],
  blockSuspiciousIPs: true,
  rateLimiting: {
    enabled: true,
    requestsPerMinute: 1000,
    burstLimit: 5000
  },
  passwordPolicy: {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSymbols: true,
    expiryDays: 90
  }
};

const mockBillingInfo: BillingInfo = {
  plan: "Enterprise",
  status: "active",
  renewalDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  amount: 499,
  currency: "USD",
  usage: {
    requests: {
      current: 2400000,
      limit: 10000000,
      period: "monthly"
    },
    storage: {
      current: 450 * 1024 * 1024 * 1024, // 450GB
      limit: 1024 * 1024 * 1024 * 1024, // 1TB
      unit: "GB"
    },
    bandwidth: {
      current: 8.2,
      limit: 20,
      unit: "TB"
    },
    compute: {
      current: 2500,
      limit: 10000,
      unit: "hours"
    }
  },
  paymentMethod: {
    type: "card",
    last4: "4242",
    brand: "Visa"
  },
  invoices: [
    {
      id: "inv_1",
      number: "INV-2024-001",
      date: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      amount: 499,
      status: "paid",
      downloadUrl: "/api/invoices/inv_1.pdf"
    },
    {
      id: "inv_2",
      number: "INV-2024-002", 
      date: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
      amount: 499,
      status: "paid",
      downloadUrl: "/api/invoices/inv_2.pdf"
    }
  ]
};

// Enhanced Premium Components
function EnterpriseCard({ children, title, description, icon: Icon, className = "" }: {
  children: React.ReactNode;
  title: string;
  description?: string;
  icon: React.ComponentType<{ className?: string }>;
  className?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -2, boxShadow: "0 20px 40px -12px rgba(0, 0, 0, 0.15)" }}
      className={`bg-white border border-gray-200/60 rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-500 overflow-hidden ${className}`}
    >
      <div className="p-8">
        <div className="flex items-center gap-4 mb-6">
          <div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl shadow-lg">
            <Icon className="w-8 h-8 text-white" />
          </div>
          <div>
            <h3 className="text-xl font-bold text-gray-900">{title}</h3>
            {description && <p className="text-gray-600 mt-1">{description}</p>}
          </div>
        </div>
        {children}
      </div>
    </motion.div>
  );
}

function MetricCard({ 
  title, 
  value, 
  change, 
  changeType, 
  icon: Icon, 
  color = "blue",
  size = "default" 
}: {
  title: string;
  value: string | number;
  change?: number;
  changeType?: "increase" | "decrease" | "neutral";
  icon: React.ComponentType<{ className?: string }>;
  color?: "blue" | "green" | "amber" | "red" | "purple";
  size?: "sm" | "default" | "lg";
}) {
  const sizeClasses = {
    sm: "p-4",
    default: "p-6", 
    lg: "p-8"
  };

  const colorClasses = {
    blue: "from-blue-500 to-blue-600",
    green: "from-emerald-500 to-emerald-600",
    amber: "from-amber-500 to-amber-600",
    red: "from-red-500 to-red-600",
    purple: "from-purple-500 to-purple-600"
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      whileHover={{ scale: 1.05 }}
      className={`${sizeClasses[size]} bg-gradient-to-br ${colorClasses[color]} rounded-2xl shadow-lg hover:shadow-2xl transition-all duration-300`}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-white/20 rounded-xl backdrop-blur-sm">
            <Icon className="w-5 h-5 text-white" />
          </div>
          <div>
            <p className="text-white/80 text-sm font-medium">{title}</p>
            <p className="text-white text-2xl font-bold">{value}</p>
          </div>
        </div>
        {change && (
          <div className={`flex items-center gap-1 px-3 py-1 bg-white/20 rounded-full backdrop-blur-sm ${
            changeType === 'increase' ? 'text-emerald-300' :
            changeType === 'decrease' ? 'text-red-300' : 
            'text-gray-300'
          }`}>
            {changeType === 'increase' ? <TrendingUp className="w-4 h-4" /> :
             changeType === 'decrease' ? <TrendingDown className="w-4 h-4" /> :
             <div className="w-4 h-4" />}
            <span className="text-sm font-medium">{Math.abs(change)}%</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function StatusIndicator({ status, size = "md", showLabel = true }: {
  status: "online" | "offline" | "warning" | "loading";
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
}) {
  const sizeClasses = {
    sm: "w-2 h-2",
    md: "w-3 h-3", 
    lg: "w-4 h-4"
  };

  const statusConfig = {
    online: { bg: "bg-emerald-500", shadow: "shadow-emerald-500/50", pulse: true, label: "Online" },
    offline: { bg: "bg-red-500", shadow: "shadow-red-500/50", pulse: false, label: "Offline" },
    warning: { bg: "bg-amber-500", shadow: "shadow-amber-500/50", pulse: true, label: "Warning" },
    loading: { bg: "bg-blue-500", shadow: "shadow-blue-500/50", pulse: true, label: "Loading" }
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center gap-2">
      <div 
        className={`${sizeClasses[size]} ${config.bg} rounded-full ${config.pulse ? 'animate-pulse' : ''}`}
        style={{ boxShadow: `0 0 20px ${config.shadow}` }}
      />
      {showLabel && (
        <span className={`text-sm font-medium ${
          status === 'online' ? 'text-emerald-700' :
          status === 'offline' ? 'text-red-700' :
          status === 'warning' ? 'text-amber-700' :
          'text-blue-700'
        }`}>
          {config.label}
        </span>
      )}
    </div>
  );
}

function PermissionToggle({ permission, onToggle }: {
  permission: Permission;
  onToggle: (granted: boolean) => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      whileHover={{ scale: 1.02 }}
      className="flex items-center justify-between p-4 bg-gray-50 rounded-xl border border-gray-200 hover:border-gray-300 transition-all duration-200"
    >
      <div className="flex items-center gap-3">
        <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
          permission.category === 'admin' ? 'bg-red-100 text-red-700' :
          permission.category === 'api' ? 'bg-blue-100 text-blue-700' :
          permission.category === 'billing' ? 'bg-green-100 text-green-700' :
          permission.category === 'security' ? 'bg-purple-100 text-purple-700' :
          'bg-gray-100 text-gray-700'
        }`}>
          {permission.category === 'admin' ? <Shield className="w-5 h-5" /> :
           permission.category === 'api' ? <Key className="w-5 h-5" /> :
           permission.category === 'billing' ? <CreditCard className="w-5 h-5" /> :
           permission.category === 'security' ? <Lock className="w-5 h-5" /> :
           <Settings className="w-5 h-5" />}
        </div>
        <div>
          <p className="font-medium text-gray-900">{permission.name}</p>
          <p className="text-sm text-gray-600">{permission.description}</p>
        </div>
      </div>
      <Switch
        checked={permission.granted}
        onCheckedChange={onToggle}
        className="scale-110"
      />
    </motion.div>
  );
}

function UsageProgress({ 
  current, 
  limit, 
  unit, 
  label, 
  color = "blue" 
}: {
  current: number;
  limit: number;
  unit: string;
  label: string;
  color?: "blue" | "green" | "amber" | "red" | "purple";
}) {
  const percentage = Math.min((current / limit) * 100, 100);
  
  const colorClasses = {
    blue: "bg-blue-500",
    green: "bg-emerald-500", 
    amber: "bg-amber-500",
    red: "bg-red-500",
    purple: "bg-purple-500"
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-gray-700">{label}</span>
        <span className="text-sm text-gray-600">
          {current.toLocaleString()} / {limit.toLocaleString()} {unit}
        </span>
      </div>
      <div className="relative">
        <Progress value={percentage} className="h-3" />
        <div 
          className={`absolute top-0 left-0 h-full ${colorClasses[color]} rounded-full transition-all duration-500`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}

export default function EnterpriseSettingsPage() {
  const [organization, setOrganization] = useState(mockOrganization);
  const [workspace, setWorkspace] = useState(mockWorkspace);
  const [members, setMembers] = useState(mockMembers);
  const [securitySettings, setSecuritySettings] = useState(mockSecuritySettings);
  const [billingInfo, setBillingInfo] = useState(mockBillingInfo);
  const [activeTab, setActiveTab] = useState("overview");
  const [isSaving, setIsSaving] = useState(false);

  const handleSaveOrganization = async () => {
    setIsSaving(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsSaving(false);
  };

  const handleInviteMember = async (email: string, role: Member["role"]) => {
    console.log(`Inviting ${email} as ${role}`);
    // Add member logic here
  };

  const handleUpdatePermission = async (memberId: string, permissionId: string, granted: boolean) => {
    console.log(`Updating permission ${permissionId} for member ${memberId} to ${granted}`);
    // Update permission logic here
  };

  return (
    <TooltipProvider>
      <div className="min-h-screen bg-gradient-to-br from-gray-50 via-white to-blue-50/30">
        <div className="max-w-7xl mx-auto p-6">
          {/* Enterprise Header */}
          <motion.div
            initial={{ opacity: 0, y: -30 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-12"
          >
            <div className="flex items-center justify-center gap-6 mb-6">
              <motion.div
                animate={{ rotate: [0, 10, -10, 0] }}
                transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                className="p-4 bg-gradient-to-br from-blue-600 via-purple-600 to-blue-700 rounded-3xl shadow-2xl"
              >
                <Settings className="w-12 h-12 text-white" />
              </motion.div>
              <div>
                <h1 className="text-5xl font-bold bg-gradient-to-r from-gray-900 to-gray-600 bg-clip-text text-transparent">
                  Enterprise Settings
                </h1>
                <p className="text-xl text-gray-600 mt-2 max-w-2xl">
                  Configure your organization's infrastructure, security, and billing preferences
                </p>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 max-w-4xl mx-auto">
              <MetricCard
                title="Team Members"
                value={members.length}
                change={12}
                changeType="increase"
                icon={Users}
                color="blue"
                size="sm"
              />
              <MetricCard
                title="API Requests"
                value={(billingInfo.usage.requests.current / 1000000).toFixed(1) + "M"}
                change={-5}
                changeType="decrease"
                icon={Activity}
                color="green"
                size="sm"
              />
              <MetricCard
                title="Storage Used"
                value={`${Math.round((billingInfo.usage.storage.current / (1024 * 1024 * 1024)))}GB`}
                change={8}
                changeType="increase"
                icon={HardDrive}
                color="amber"
                size="sm"
              />
              <MetricCard
                title="Security Score"
                value="98%"
                change={2}
                changeType="increase"
                icon={ShieldCheck}
                color="purple"
                size="sm"
              />
            </div>
          </motion.div>

          {/* Main Settings */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-8">
            <TabsList className="grid w-full grid-cols-6 h-auto p-1 bg-gray-100/80 backdrop-blur-sm rounded-2xl shadow-lg">
              <TabsTrigger value="overview" className="data-[state=active]:bg-white data-[state=active]:shadow-md rounded-xl transition-all duration-200">
                <div className="flex flex-col items-center gap-2">
                  <Globe className="w-5 h-5" />
                  <span className="text-sm font-medium">Overview</span>
                </div>
              </TabsTrigger>
              <TabsTrigger value="organization" className="data-[state=active]:bg-white data-[state=active]:shadow-md rounded-xl transition-all duration-200">
                <div className="flex flex-col items-center gap-2">
                  <Building2 className="w-5 h-5" />
                  <span className="text-sm font-medium">Organization</span>
                </div>
              </TabsTrigger>
              <TabsTrigger value="workspace" className="data-[state=active]:bg-white data-[state=active]:shadow-md rounded-xl transition-all duration-200">
                <div className="flex flex-col items-center gap-2">
                  <Server className="w-5 h-5" />
                  <span className="text-sm font-medium">Workspace</span>
                </div>
              </TabsTrigger>
              <TabsTrigger value="members" className="data-[state=active]:bg-white data-[state=active]:shadow-md rounded-xl transition-all duration-200">
                <div className="flex flex-col items-center gap-2">
                  <Users className="w-5 h-5" />
                  <span className="text-sm font-medium">Members</span>
                </div>
              </TabsTrigger>
              <TabsTrigger value="security" className="data-[state=active]:bg-white data-[state=active]:shadow-md rounded-xl transition-all duration-200">
                <div className="flex flex-col items-center gap-2">
                  <Shield className="w-5 h-5" />
                  <span className="text-sm font-medium">Security</span>
                </div>
              </TabsTrigger>
              <TabsTrigger value="billing" className="data-[state=active]:bg-white data-[state=active]:shadow-md rounded-xl transition-all duration-200">
                <div className="flex flex-col items-center gap-2">
                  <CreditCard className="w-5 h-5" />
                  <span className="text-sm font-medium">Billing</span>
                </div>
              </TabsTrigger>
            </TabsList>

            {/* Overview Tab */}
            <TabsContent value="overview" className="space-y-8">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <EnterpriseCard title="System Health" icon={Activity} description="Real-time infrastructure monitoring">
                  <div className="space-y-6">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="flex items-center gap-3">
                        <StatusIndicator status="online" />
                        <div>
                          <p className="text-sm text-gray-600">API Status</p>
                          <p className="font-medium">Operational</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <StatusIndicator status="online" />
                        <div>
                          <p className="text-sm text-gray-600">Database</p>
                          <p className="font-medium">Healthy</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <StatusIndicator status="warning" />
                        <div>
                          <p className="text-sm text-gray-600">Cache Layer</p>
                          <p className="font-medium">Degraded</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <StatusIndicator status="online" />
                        <div>
                          <p className="text-sm text-gray-600">CDN</p>
                          <p className="font-medium">Optimal</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </EnterpriseCard>

                <EnterpriseCard title="Resource Usage" icon={BarChart3} description="Current utilization metrics">
                  <div className="space-y-6">
                    <UsageProgress
                      current={billingInfo.usage.requests.current}
                      limit={billingInfo.usage.requests.limit}
                      unit="requests"
                      label="API Requests"
                      color="blue"
                    />
                    <UsageProgress
                      current={billingInfo.usage.storage.current}
                      limit={billingInfo.usage.storage.limit}
                      unit="GB"
                      label="Storage"
                      color="green"
                    />
                    <UsageProgress
                      current={billingInfo.usage.bandwidth.current}
                      limit={billingInfo.usage.bandwidth.limit}
                      unit="TB"
                      label="Bandwidth"
                      color="amber"
                    />
                    <UsageProgress
                      current={billingInfo.usage.compute.current}
                      limit={billingInfo.usage.compute.limit}
                      unit="hours"
                      label="Compute Time"
                      color="purple"
                    />
                  </div>
                </EnterpriseCard>
              </div>
            </TabsContent>

            {/* Organization Tab */}
            <TabsContent value="organization">
              <EnterpriseCard title="Organization Settings" icon={Building2} description="Manage your organization's basic information">
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <Label htmlFor="org-name">Organization Name</Label>
                      <Input
                        id="org-name"
                        value={organization.name}
                        onChange={(e) => setOrganization(prev => ({ ...prev, name: e.target.value }))}
                        placeholder="Acme Corporation"
                        className="h-12"
                      />
                    </div>
                    <div className="space-y-3">
                      <Label htmlFor="org-domain">Primary Domain</Label>
                      <Input
                        id="org-domain"
                        value={organization.domain}
                        onChange={(e) => setOrganization(prev => ({ ...prev, domain: e.target.value }))}
                        placeholder="api.acme.com"
                        className="h-12"
                      />
                    </div>
                  </div>
                  
                  <div className="space-y-3">
                    <Label htmlFor="org-website">Website</Label>
                    <Input
                      id="org-website"
                      value={organization.website}
                      onChange={(e) => setOrganization(prev => ({ ...prev, website: e.target.value }))}
                      placeholder="https://acme.com"
                      className="h-12"
                    />
                  </div>

                  <div className="space-y-3">
                    <Label htmlFor="org-description">Description</Label>
                    <Textarea
                      id="org-description"
                      value={organization.description}
                      onChange={(e) => setOrganization(prev => ({ ...prev, description: e.target.value }))}
                      placeholder="Brief description of your organization"
                      rows={4}
                      className="resize-none"
                    />
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="space-y-3">
                      <Label htmlFor="org-industry">Industry</Label>
                      <Select value={organization.industry} onValueChange={(value) => setOrganization(prev => ({ ...prev, industry: value }))}>
                        <SelectTrigger className="h-12">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="technology">Technology</SelectItem>
                          <SelectItem value="healthcare">Healthcare</SelectItem>
                          <SelectItem value="finance">Finance</SelectItem>
                          <SelectItem value="education">Education</SelectItem>
                          <SelectItem value="retail">Retail</SelectItem>
                          <SelectItem value="manufacturing">Manufacturing</SelectItem>
                          <SelectItem value="government">Government</SelectItem>
                          <SelectItem value="other">Other</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-3">
                      <Label htmlFor="org-size">Organization Size</Label>
                      <Select value={organization.size} onValueChange={(value) => setOrganization(prev => ({ ...prev, size: value as Organization["size"] }))}>
                        <SelectTrigger className="h-12">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="startup">Startup (1-10)</SelectItem>
                          <SelectItem value="small">Small (11-50)</SelectItem>
                          <SelectItem value="medium">Medium (51-200)</SelectItem>
                          <SelectItem value="large">Large (201-1000)</SelectItem>
                          <SelectItem value="enterprise">Enterprise (1000+)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-3">
                      <Label htmlFor="org-timezone">Timezone</Label>
                      <Select value={organization.timezone} onValueChange={(value) => setOrganization(prev => ({ ...prev, timezone: value }))}>
                        <SelectTrigger className="h-12">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="UTC">UTC</SelectItem>
                          <SelectItem value="America/New_York">America/New_York</SelectItem>
                          <SelectItem value="Europe/London">Europe/London</SelectItem>
                          <SelectItem value="Asia/Tokyo">Asia/Tokyo</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 pt-6 border-t">
                    <Button variant="outline" className="flex items-center gap-2">
                      <Upload className="w-4 h-4" />
                      Upload Logo
                    </Button>
                    <Button 
                      onClick={handleSaveOrganization}
                      disabled={isSaving}
                      className="flex-1 flex items-center gap-2"
                    >
                      {isSaving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                      {isSaving ? "Saving..." : "Save Changes"}
                    </Button>
                  </div>
                </div>
              </EnterpriseCard>
            </TabsContent>

            {/* Workspace Tab */}
            <TabsContent value="workspace">
              <EnterpriseCard title="Workspace Configuration" icon={Server} description="Configure your workspace environment and quotas">
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <Label htmlFor="workspace-name">Workspace Name</Label>
                      <Input
                        id="workspace-name"
                        value={workspace.name}
                        onChange={(e) => setWorkspace(prev => ({ ...prev, name: e.target.value }))}
                        placeholder="Production Workspace"
                        className="h-12"
                      />
                    </div>
                    <div className="space-y-3">
                      <Label htmlFor="workspace-id">Workspace ID</Label>
                      <Input
                        id="workspace-id"
                        value={workspace.id}
                        disabled
                        className="h-12 bg-gray-50"
                      />
                      <p className="text-xs text-gray-500 mt-1">This ID cannot be changed</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-3">
                      <Label htmlFor="environment">Default Environment</Label>
                      <Select value={workspace.environment} onValueChange={(value) => setWorkspace(prev => ({ ...prev, environment: value as Workspace["environment"] }))}>
                        <SelectTrigger className="h-12">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="production">🔴 Production</SelectItem>
                          <SelectItem value="staging">🟡 Staging</SelectItem>
                          <SelectItem value="development">🟢 Development</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-3">
                      <Label htmlFor="region">Data Region</Label>
                      <Select value={workspace.region} onValueChange={(value) => setWorkspace(prev => ({ ...prev, region: value as Workspace["region"] }))}>
                        <SelectTrigger className="h-12">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="us">🇺🇸 United States</SelectItem>
                          <SelectItem value="eu">🇪🇺 European Union</SelectItem>
                          <SelectItem value="asia">🌏 Asia Pacific</SelectItem>
                          <SelectItem value="custom">🌍 Custom Region</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-6">
                    <h4 className="text-lg font-semibold text-gray-900 mb-4">Resource Quotas</h4>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="space-y-3">
                        <Label htmlFor="api-quota">API Quota (requests/month)</Label>
                        <Input
                          id="api-quota"
                          type="number"
                          value={workspace.apiQuota}
                          onChange={(e) => setWorkspace(prev => ({ ...prev, apiQuota: parseInt(e.target.value) }))}
                          className="h-12"
                        />
                      </div>
                      <div className="space-y-3">
                        <Label htmlFor="storage-quota">Storage Quota (GB)</Label>
                        <Input
                          id="storage-quota"
                          type="number"
                          value={workspace.storageQuota / (1024 * 1024 * 1024)}
                          onChange={(e) => setWorkspace(prev => ({ ...prev, storageQuota: parseInt(e.target.value) * 1024 * 1024 * 1024 }))}
                          className="h-12"
                        />
                      </div>
                      <div className="space-y-3">
                        <Label htmlFor="bandwidth-quota">Bandwidth Quota (GB/month)</Label>
                        <Input
                          id="bandwidth-quota"
                          type="number"
                          value={workspace.bandwidthQuota / (1024 * 1024 * 1024)}
                          onChange={(e) => setWorkspace(prev => ({ ...prev, bandwidthQuota: parseInt(e.target.value) * 1024 * 1024 * 1024 }))}
                          className="h-12"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-4 pt-6 border-t">
                    <Button className="flex-1 flex items-center gap-2">
                      <Save className="w-4 h-4" />
                      Save Workspace Settings
                    </Button>
                  </div>
                </div>
              </EnterpriseCard>
            </TabsContent>

            {/* Members Tab */}
            <TabsContent value="members">
              <div className="space-y-8">
                <EnterpriseCard 
                  title="Team Management" 
                  icon={Users} 
                  description="Manage team members and their access permissions"
                  className="mb-8"
                >
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-blue-100 rounded-lg">
                        <UserPlus className="w-5 h-5 text-blue-700" />
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">Invite Team Member</p>
                        <p className="text-sm text-gray-600">Add new members to your organization</p>
                      </div>
                    </div>
                    <Dialog>
                      <DialogTrigger asChild>
                        <Button className="flex items-center gap-2">
                          <Mail className="w-4 h-4" />
                          Send Invitation
                        </Button>
                      </DialogTrigger>
                      <DialogContent className="sm:max-w-md">
                        <DialogHeader>
                          <DialogTitle>Invite Team Member</DialogTitle>
                          <DialogDescription>
                            Send an invitation to join your organization
                          </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4">
                          <div>
                            <Label htmlFor="invite-email">Email address</Label>
                            <Input
                              id="invite-email"
                              type="email"
                              placeholder="colleague@company.com"
                            />
                          </div>
                          <div>
                            <Label htmlFor="invite-role">Role</Label>
                            <Select>
                              <SelectTrigger>
                                <SelectValue placeholder="Select a role" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="owner">Owner - Full control</SelectItem>
                                <SelectItem value="admin">Admin - Management access</SelectItem>
                                <SelectItem value="developer">Developer - API access</SelectItem>
                                <SelectItem value="analyst">Analyst - Read-only access</SelectItem>
                                <SelectItem value="viewer">Viewer - Limited access</SelectItem>
                                <SelectItem value="custom">Custom permissions</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="flex gap-2 pt-4">
                            <Button variant="outline" className="flex-1">Cancel</Button>
                            <Button onClick={() => handleInviteMember("email@example.com", "developer")} className="flex-1">
                              <Mail className="w-4 h-4 mr-2" />
                              Send Invitation
                            </Button>
                          </div>
                        </div>
                      </DialogContent>
                    </Dialog>
                  </div>
                </EnterpriseCard>

                {/* Members Table */}
                <Card className="border-0 shadow-lg overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-gray-50">
                        <TableHead className="font-semibold">Member</TableHead>
                        <TableHead className="font-semibold">Role</TableHead>
                        <TableHead className="font-semibold">Status</TableHead>
                        <TableHead className="font-semibold">Last Activity</TableHead>
                        <TableHead className="font-semibold">2FA</TableHead>
                        <TableHead className="font-semibold text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {members.map((member) => (
                        <TableRow key={member.id} className="hover:bg-gray-50 transition-colors">
                          <TableCell className="py-4">
                            <div className="flex items-center gap-3">
                              <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white font-bold text-sm shadow-lg">
                                {member.avatar}
                              </div>
                              <div>
                                <div className="font-medium text-gray-900">{member.name}</div>
                                <div className="text-sm text-gray-600">{member.email}</div>
                                {member.department && (
                                  <div className="text-xs text-gray-500">{member.department}</div>
                                )}
                              </div>
                            </div>
                          </TableCell>
                          <TableCell className="py-4">
                            <Badge className={
                              member.role === 'owner' ? 'bg-gradient-to-r from-purple-500 to-purple-600 text-white' :
                              member.role === 'admin' ? 'bg-red-100 text-red-800' :
                              member.role === 'developer' ? 'bg-blue-100 text-blue-800' :
                              member.role === 'analyst' ? 'bg-green-100 text-green-800' :
                              'bg-gray-100 text-gray-800'
                            }>
                              {member.role === 'owner' && <Crown className="w-3 h-3 mr-1" />}
                              {member.role}
                            </Badge>
                          </TableCell>
                          <TableCell className="py-4">
                            <StatusIndicator 
                              status={
                                member.status === 'active' ? 'online' :
                                member.status === 'pending' ? 'warning' :
                                member.status === 'suspended' ? 'offline' : 'offline'
                              } 
                            />
                          </TableCell>
                          <TableCell className="py-4">
                            <div className="text-sm text-gray-600">
                              <div>{member.lastActivity.toLocaleDateString()}</div>
                              {member.lastLogin && (
                                <div className="text-xs text-gray-500">Last login: {member.lastLogin.toLocaleString()}</div>
                              )}
                            </div>
                          </TableCell>
                          <TableCell className="py-4">
                            <StatusIndicator 
                              status={member.mfaEnabled ? 'online' : 'offline'}
                              size="sm"
                              showLabel={false}
                            />
                          </TableCell>
                          <TableCell className="py-4 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <Button variant="outline" size="sm">
                                <UserCog className="w-4 h-4" />
                              </Button>
                              <Button variant="outline" size="sm" className="text-red-600 hover:text-red-700">
                                <UserX className="w-4 h-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              </div>
            </TabsContent>

            {/* Security Tab */}
            <TabsContent value="security">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <EnterpriseCard title="Authentication" icon={Lock} description="Configure authentication and session policies">
                  <div className="space-y-6">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Enforce 2FA</p>
                          <p className="text-sm text-gray-600">Require two-factor authentication for all users</p>
                        </div>
                        <Switch 
                          checked={securitySettings.enforce2FA} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ ...prev, enforce2FA: checked }))}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Require SSO</p>
                          <p className="text-sm text-gray-600">Force SAML/OIDC authentication</p>
                        </div>
                        <Switch 
                          checked={securitySettings.requireSSO} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ ...prev, requireSSO: checked }))}
                        />
                      </div>
                    </div>

                    <div className="space-y-3">
                      <Label htmlFor="session-timeout">Session Timeout (hours)</Label>
                      <Slider
                        id="session-timeout"
                        min={1}
                        max={168}
                        step={1}
                        value={[securitySettings.sessionTimeout]}
                        onValueChange={([value]) => setSecuritySettings(prev => ({ ...prev, sessionTimeout: value }))}
                        className="mt-2"
                      />
                      <div className="flex justify-between text-sm text-gray-600 mt-1">
                        <span>1 hour</span>
                        <span>{securitySettings.sessionTimeout} hours</span>
                        <span>7 days</span>
                      </div>
                    </div>

                    <div className="pt-4 border-t">
                      <Button variant="outline" className="w-full flex items-center gap-2">
                        <RefreshCw className="w-4 h-4" />
                        Regenerate API Credentials
                      </Button>
                    </div>
                  </div>
                </EnterpriseCard>

                <EnterpriseCard title="Password Policy" icon={KeyRound} description="Configure password requirements">
                  <div className="space-y-6">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Minimum Length</p>
                          <p className="text-sm text-gray-600">Characters required</p>
                        </div>
                        <Input
                          type="number"
                          value={securitySettings.passwordPolicy.minLength}
                          onChange={(e) => setSecuritySettings(prev => ({ 
                            ...prev, 
                            passwordPolicy: { ...prev.passwordPolicy, minLength: parseInt(e.target.value) }
                          }))}
                          className="w-20"
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Require Uppercase</p>
                          <p className="text-sm text-gray-600">A-Z letters</p>
                        </div>
                        <Switch 
                          checked={securitySettings.passwordPolicy.requireUppercase} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ 
                            ...prev, 
                            passwordPolicy: { ...prev.passwordPolicy, requireUppercase: checked }
                          }))}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Require Lowercase</p>
                          <p className="text-sm text-gray-600">a-z letters</p>
                        </div>
                        <Switch 
                          checked={securitySettings.passwordPolicy.requireLowercase} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ 
                            ...prev, 
                            passwordPolicy: { ...prev.passwordPolicy, requireLowercase: checked }
                          }))}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Require Numbers</p>
                          <p className="text-sm text-gray-600">0-9 digits</p>
                        </div>
                        <Switch 
                          checked={securitySettings.passwordPolicy.requireNumbers} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ 
                            ...prev, 
                            passwordPolicy: { ...prev.passwordPolicy, requireNumbers: checked }
                          }))}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Require Symbols</p>
                          <p className="text-sm text-gray-600">Special characters</p>
                        </div>
                        <Switch 
                          checked={securitySettings.passwordPolicy.requireSymbols} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ 
                            ...prev, 
                            passwordPolicy: { ...prev.passwordPolicy, requireSymbols: checked }
                          }))}
                        />
                      </div>
                    </div>

                    <div className="space-y-3">
                      <Label htmlFor="password-expiry">Password Expiry (days)</Label>
                      <Slider
                        id="password-expiry"
                        min={30}
                        max={365}
                        step={1}
                        value={[securitySettings.passwordPolicy.expiryDays]}
                        onValueChange={([value]) => setSecuritySettings(prev => ({ 
                          ...prev, 
                          passwordPolicy: { ...prev.passwordPolicy, expiryDays: value }
                        }))}
                        className="mt-2"
                      />
                      <div className="flex justify-between text-sm text-gray-600 mt-1">
                        <span>30 days</span>
                        <span>{securitySettings.passwordPolicy.expiryDays} days</span>
                        <span>365 days</span>
                      </div>
                    </div>
                  </div>
                </EnterpriseCard>

                <EnterpriseCard title="Network Security" icon={ShieldAlert} description="Configure network access controls">
                  <div className="space-y-6">
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Block Suspicious IPs</p>
                          <p className="text-sm text-gray-600">Automatic IP blocking</p>
                        </div>
                        <Switch 
                          checked={securitySettings.blockSuspiciousIPs} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ ...prev, blockSuspiciousIPs: checked }))}
                        />
                      </div>
                      
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-gray-900">Rate Limiting</p>
                          <p className="text-sm text-gray-600">DDoS protection</p>
                        </div>
                        <Switch 
                          checked={securitySettings.rateLimiting.enabled} 
                          onCheckedChange={(checked) => setSecuritySettings(prev => ({ 
                            ...prev, 
                            rateLimiting: { ...prev.rateLimiting, enabled: checked }
                          }))}
                        />
                      </div>
                    </div>

                    {securitySettings.rateLimiting.enabled && (
                      <div className="space-y-4 p-4 bg-gray-50 rounded-lg">
                        <div className="space-y-3">
                          <Label htmlFor="rate-limit-requests">Requests per Minute</Label>
                          <Input
                            id="rate-limit-requests"
                            type="number"
                            value={securitySettings.rateLimiting.requestsPerMinute}
                            onChange={(e) => setSecuritySettings(prev => ({ 
                              ...prev, 
                              rateLimiting: { ...prev.rateLimiting, requestsPerMinute: parseInt(e.target.value) }
                            }))}
                          />
                        </div>
                        <div className="space-y-3">
                          <Label htmlFor="rate-limit-burst">Burst Limit</Label>
                          <Input
                            id="rate-limit-burst"
                            type="number"
                            value={securitySettings.rateLimiting.burstLimit}
                            onChange={(e) => setSecuritySettings(prev => ({ 
                              ...prev, 
                              rateLimiting: { ...prev.rateLimiting, burstLimit: parseInt(e.target.value) }
                            }))}
                          />
                        </div>
                      </div>
                    )}

                    <div className="space-y-3">
                      <Label htmlFor="ip-allowlist">IP Allowlist</Label>
                      <Textarea
                        id="ip-allowlist"
                        value={securitySettings.ipAllowlist.join('\n')}
                        onChange={(e) => setSecuritySettings(prev => ({ 
                          ...prev, 
                          ipAllowlist: e.target.value.split('\n').filter(ip => ip.trim())
                        }))}
                        placeholder="192.168.1.0/24&#10;10.0.0.0/8"
                        rows={4}
                      />
                      <p className="text-xs text-gray-500 mt-1">Enter IP addresses or CIDR blocks, one per line</p>
                    </div>
                  </div>
                </EnterpriseCard>
              </div>
            </TabsContent>

            {/* Billing Tab */}
            <TabsContent value="billing">
              <div className="space-y-8">
                <EnterpriseCard title="Current Plan" icon={Crown} description="Your subscription details and usage">
                  <div className="space-y-6">
                    <div className="p-6 bg-gradient-to-r from-blue-50 to-purple-50 border border-blue-200 rounded-2xl">
                      <div className="flex items-center justify-between mb-4">
                        <span className="text-sm font-medium text-gray-600">Current Plan</span>
                        <Badge className="bg-gradient-to-r from-blue-600 to-purple-600 text-white text-sm px-4 py-2">
                          <Crown className="w-4 h-4 mr-2" />
                          Enterprise
                        </Badge>
                      </div>
                      <div className="text-3xl font-bold text-gray-900 mb-2">${billingInfo.amount}/month</div>
                      <div className="text-sm text-gray-600">
                        Renews on {billingInfo.renewalDate.toLocaleDateString()}
                      </div>
                      <div className="flex items-center gap-2 pt-4">
                        <StatusIndicator status={billingInfo.status === 'active' ? 'online' : 'warning'} />
                        <span className="text-sm font-medium capitalize">{billingInfo.status}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="space-y-3">
                        <Label htmlFor="payment-method">Payment Method</Label>
                        <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-lg">
                          <div className="p-2 bg-white rounded-lg">
                            <CreditCard className="w-6 h-6 text-gray-700" />
                          </div>
                          <div>
                            <p className="font-medium">••••• {billingInfo.paymentMethod.last4}</p>
                            <p className="text-sm text-gray-600 capitalize">{billingInfo.paymentMethod.brand}</p>
                          </div>
                        </div>
                      </div>
                      <div className="space-y-3">
                        <Label htmlFor="billing-email">Billing Email</Label>
                        <Input
                          id="billing-email"
                          type="email"
                          defaultValue="billing@skygenesis.com"
                          className="h-12"
                        />
                      </div>
                    </div>

                    <div className="flex gap-4 pt-4 border-t">
                      <Button variant="outline" className="flex items-center gap-2">
                        <CreditCard className="w-4 h-4" />
                        Update Payment Method
                      </Button>
                      <Button className="flex items-center gap-2">
                        <Download className="w-4 h-4" />
                        Download Invoices
                      </Button>
                    </div>
                  </div>
                </EnterpriseCard>

                {/* Recent Invoices */}
                <Card className="border-0 shadow-lg">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="w-5 h-5" />
                      Recent Invoices
                    </CardTitle>
                    <CardDescription>
                      Download your billing statements and receipts
                    </CardDescription>
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
                        {billingInfo.invoices.map((invoice) => (
                          <TableRow key={invoice.id}>
                            <TableCell className="font-medium">{invoice.number}</TableCell>
                            <TableCell>{invoice.date.toLocaleDateString()}</TableCell>
                            <TableCell className="font-medium">${invoice.amount}</TableCell>
                            <TableCell>
                              <Badge className={
                                invoice.status === 'paid' ? 'bg-emerald-100 text-emerald-800' :
                                invoice.status === 'pending' ? 'bg-amber-100 text-amber-800' :
                                'bg-red-100 text-red-800'
                              }>
                                {invoice.status}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-right">
                              <Button variant="outline" size="sm">
                                <Download className="w-4 h-4" />
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </TooltipProvider>
  );
}