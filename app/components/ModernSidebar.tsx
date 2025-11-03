"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '../context/JwtAuthContext';
import { useSidebar } from '../context/SidebarContext';
import { motion, AnimatePresence, Variants } from 'framer-motion';
import {
  LayoutDashboard,
  Users,
  Settings,
  FileText,
  User,
  Inbox,
  BookOpen,
  LogOut,
  Menu,
  X,
  ChevronRight,
  Shield,
  Key,
  AlertTriangle,
  FileCheck,
  Sun,
  Moon
} from 'lucide-react';
import { Button } from './ui/button';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from './ui/tooltip';
import { Switch } from './ui/switch';

interface NavItem {
  name: string;
  href: string;
  icon: React.ReactNode;
  children?: NavItem[];
}

const navigationItems: NavItem[] = [
  {
    name: 'Dashboard',
    href: '/dashboard',
    icon: <LayoutDashboard className="w-5 h-5" />,
  },
  {
    name: 'Users',
    href: '/users',
    icon: <Users className="w-5 h-5" />,
  },
  {
    name: 'Projects',
    href: '/projects',
    icon: <BookOpen className="w-5 h-5" />,
  },
  {
    name: 'Inbox',
    href: '/inbox',
    icon: <Inbox className="w-5 h-5" />,
  },
  {
    name: 'Settings',
    href: '/settings',
    icon: <Settings className="w-5 h-5" />,
    children: [
      {
        name: 'General',
        href: '/settings/general',
        icon: <Settings className="w-4 h-4" />,
      },
      {
        name: 'API Keys',
        href: '/settings/api',
        icon: <Key className="w-4 h-4" />,
      },
      {
        name: 'Security',
        href: '/settings/security',
        icon: <Shield className="w-4 h-4" />,
      },
    ],
  },
  {
    name: 'Logs',
    href: '/logs',
    icon: <FileText className="w-5 h-5" />,
    children: [
      {
        name: 'Activity',
        href: '/logs',
        icon: <FileCheck className="w-4 h-4" />,
      },
      {
        name: 'Errors',
        href: '/logs/errors',
        icon: <AlertTriangle className="w-4 h-4" />,
      },
    ],
  },
];

export default function ModernSidebar() {
  const { user, logout } = useAuth();
  const { isCollapsed, setIsCollapsed } = useSidebar();
  const pathname = usePathname();
  const [openDropdowns, setOpenDropdowns] = useState<Set<string>>(new Set());
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);

  const handleLogout = async () => {
    await logout();
  };

  const toggleDropdown = (name: string) => {
    const newOpenDropdowns = new Set(openDropdowns);
    if (newOpenDropdowns.has(name)) {
      newOpenDropdowns.delete(name);
    } else {
      newOpenDropdowns.add(name);
    }
    setOpenDropdowns(newOpenDropdowns);
  };

  const isActive = (href: string) => {
    if (href === '/dashboard' && pathname === '/') return true;
    return pathname === href || pathname.startsWith(href + '/');
  };

  const isDropdownActive = (item: NavItem) => {
    if (item.children) {
      return item.children.some(child => isActive(child.href));
    }
    return isActive(item.href);
  };

  // Auto-expand dropdowns for active sections
  useEffect(() => {
    const activeDropdowns = new Set<string>();
    navigationItems.forEach(item => {
      if (item.children && isDropdownActive(item)) {
        activeDropdowns.add(item.name);
      }
    });
    setOpenDropdowns(activeDropdowns);
  }, [pathname]);

  // Theme management
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setIsDarkMode(savedTheme === 'dark' || (!savedTheme && prefersDark));
  }, []);

  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  }, [isDarkMode]);

  if (pathname.startsWith('/auth') || pathname === '/login') {
    return null;
  }

  const sidebarVariants: Variants = {
    expanded: { width: 260, transition: { duration: 0.3, ease: "easeInOut" as const } },
    collapsed: { width: 80, transition: { duration: 0.3, ease: "easeInOut" as const } },
  };

  const navItemVariants: Variants = {
    expanded: { 
      opacity: 1, 
      x: 0,
      transition: { duration: 0.2, ease: "easeOut" as const }
    },
    collapsed: { 
      opacity: 0, 
      x: -20,
      transition: { duration: 0.2, ease: "easeIn" as const }
    },
  };

  const renderNavItem = (item: NavItem, isMobile = false) => {
    const active = isActive(item.href);
    const dropdownActive = isDropdownActive(item);
    const hasChildren = item.children && item.children.length > 0;
    const isCollapsedState = isMobile ? false : isCollapsed;

    if (hasChildren) {
      return (
        <div key={item.name} className="w-full">
          <TooltipProvider delayDuration={0}>
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => toggleDropdown(item.name)}
                  className={`w-full flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${
                    dropdownActive
                      ? 'bg-black text-white dark:bg-white dark:text-black'
                      : 'text-gray-600 hover:text-black hover:bg-gray-100 dark:text-gray-400 dark:hover:text-white dark:hover:bg-gray-800'
                  } ${isCollapsedState ? 'justify-center' : 'justify-between'}`}
                >
                  <div className="flex items-center space-x-3">
                    <div className={`transition-transform duration-200 ${dropdownActive ? 'scale-110' : 'group-hover:scale-105'}`}>
                      {item.icon}
                    </div>
                    {!isCollapsedState && (
                      <motion.span
                        variants={navItemVariants}
                        initial="collapsed"
                        animate="expanded"
                        className="truncate"
                      >
                        {item.name}
                      </motion.span>
                    )}
                  </div>
                  {!isCollapsedState && (
                    <motion.div
                      variants={navItemVariants}
                      initial="collapsed"
                      animate="expanded"
                    >
                      <ChevronRight className={`w-4 h-4 transition-transform duration-200 ${
                        openDropdowns.has(item.name) ? 'rotate-90' : ''
                      }`} />
                    </motion.div>
                  )}
                </button>
              </TooltipTrigger>
              {isCollapsedState && (
                <TooltipContent side="right" className="ml-2">
                  <p>{item.name}</p>
                </TooltipContent>
              )}
            </Tooltip>
          </TooltipProvider>

          <AnimatePresence>
            {openDropdowns.has(item.name) && !isCollapsedState && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2, ease: "easeInOut" as const }}
                className="ml-6 mt-1 space-y-1"
              >
                {item.children!.map((child) => (
                  <TooltipProvider delayDuration={0} key={child.href}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Link
                          href={child.href}
                          className={`flex items-center space-x-3 px-3 py-2 rounded-lg text-sm transition-all duration-200 group ${
                            isActive(child.href)
                              ? 'bg-black text-white dark:bg-white dark:text-black'
                              : 'text-gray-500 hover:text-black hover:bg-gray-100 dark:text-gray-500 dark:hover:text-white dark:hover:bg-gray-800'
                          }`}
                        >
                          <div className={`transition-transform duration-200 ${isActive(child.href) ? 'scale-110' : 'group-hover:scale-105'}`}>
                            {child.icon}
                          </div>
                          <motion.span
                            variants={navItemVariants}
                            initial="collapsed"
                            animate="expanded"
                            className="truncate"
                          >
                            {child.name}
                          </motion.span>
                        </Link>
                      </TooltipTrigger>
                    </Tooltip>
                  </TooltipProvider>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      );
    }

    return (
      <TooltipProvider delayDuration={0} key={item.href}>
        <Tooltip>
          <TooltipTrigger asChild>
            <Link
              href={item.href}
              className={`flex items-center px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 group ${
                active
                  ? 'bg-black text-white dark:bg-white dark:text-black'
                  : 'text-gray-600 hover:text-black hover:bg-gray-100 dark:text-gray-400 dark:hover:text-white dark:hover:bg-gray-800'
              } ${isCollapsedState ? 'justify-center' : 'space-x-3'}`}
            >
              <div className={`transition-transform duration-200 ${active ? 'scale-110' : 'group-hover:scale-105'}`}>
                {item.icon}
              </div>
              {!isCollapsedState && (
                <motion.span
                  variants={navItemVariants}
                  initial="collapsed"
                  animate="expanded"
                  className="truncate"
                >
                  {item.name}
                </motion.span>
              )}
            </Link>
          </TooltipTrigger>
          {isCollapsedState && (
            <TooltipContent side="right" className="ml-2">
              <p>{item.name}</p>
            </TooltipContent>
          )}
        </Tooltip>
      </TooltipProvider>
    );
  };

  return (
    <>
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-4 left-4 z-50">
        <Button
          variant="outline"
          size="icon"
          onClick={() => setIsMobileOpen(!isMobileOpen)}
          className="bg-white dark:bg-black border-gray-200 dark:border-gray-800"
        >
          {isMobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </Button>
      </div>

      {/* Mobile overlay */}
      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="lg:hidden fixed inset-0 bg-black/20 dark:bg-white/20 z-30"
            onClick={() => setIsMobileOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Mobile sidebar */}
      <AnimatePresence>
        {isMobileOpen && (
          <motion.div
            initial={{ x: -300 }}
            animate={{ x: 0 }}
            exit={{ x: -300 }}
            transition={{ duration: 0.3, ease: "easeInOut" as const }}
            className="lg:hidden fixed left-0 top-0 h-full bg-white dark:bg-black border-r border-gray-200 dark:border-gray-800 shadow-xl z-40 w-72"
          >
            {/* Mobile header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-800">
              <Link
                href="/dashboard"
                className="flex items-center space-x-3 text-lg font-bold text-black dark:text-white hover:opacity-80 transition-opacity"
                onClick={() => setIsMobileOpen(false)}
              >
                <div className="w-8 h-8 bg-black dark:bg-white rounded-lg flex items-center justify-center">
                  <span className="text-white dark:text-black font-bold text-sm">SG</span>
                </div>
                <span>Sky Genesis</span>
              </Link>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsMobileOpen(false)}
                className="text-gray-500 hover:text-black dark:text-gray-400 dark:hover:text-white"
              >
                <X className="w-5 h-5" />
              </Button>
            </div>

            {/* Mobile Navigation */}
            <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
              {navigationItems.map((item) => renderNavItem(item, true))}
            </nav>

            {/* Mobile footer */}
            <div className="border-t border-gray-200 dark:border-gray-800 p-4 space-y-3">
              {user && (
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-black dark:bg-white rounded-full flex items-center justify-center">
                    <span className="text-white dark:text-black text-sm font-medium">
                      {(user.fullName || user.email || 'U').charAt(0).toUpperCase()}
                    </span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-black dark:text-white truncate">
                      {user.fullName || user.email}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                      {user.email}
                    </p>
                  </div>
                </div>
              )}
              <Button
                variant="outline"
                onClick={handleLogout}
                className="w-full justify-start text-gray-600 hover:text-black dark:text-gray-400 dark:hover:text-white border-gray-200 dark:border-gray-800"
              >
                <LogOut className="w-4 h-4 mr-2" />
                Logout
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Desktop Sidebar */}
      <motion.div
        variants={sidebarVariants}
        animate={isCollapsed ? "collapsed" : "expanded"}
        className="hidden lg:block fixed left-0 top-0 h-full bg-white dark:bg-black border-r border-gray-200 dark:border-gray-800 shadow-sm z-40"
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-800">
          {!isCollapsed && (
            <Link
              href="/dashboard"
              className="flex items-center space-x-3 text-lg font-bold text-black dark:text-white hover:opacity-80 transition-opacity"
            >
              <div className="w-8 h-8 bg-black dark:bg-white rounded-lg flex items-center justify-center">
                <span className="text-white dark:text-black font-bold text-sm">SG</span>
              </div>
              <motion.span
                variants={navItemVariants}
                initial="collapsed"
                animate="expanded"
                className="truncate"
              >
                Sky Genesis
              </motion.span>
            </Link>
          )}
          {isCollapsed && (
            <Link
              href="/dashboard"
              className="flex justify-center w-full"
            >
              <div className="w-8 h-8 bg-black dark:bg-white rounded-lg flex items-center justify-center">
                <span className="text-white dark:text-black font-bold text-sm">SG</span>
              </div>
            </Link>
          )}

          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className="text-gray-500 hover:text-black dark:text-gray-400 dark:hover:text-white"
          >
            <ChevronRight className={`w-4 h-4 transition-transform duration-200 ${
              isCollapsed ? '' : 'rotate-180'
            }`} />
          </Button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navigationItems.map((item) => renderNavItem(item))}
        </nav>

        {/* Footer */}
        <div className="border-t border-gray-200 dark:border-gray-800 p-4 space-y-3">
          {!isCollapsed && user && (
            <motion.div
              variants={navItemVariants}
              initial="collapsed"
              animate="expanded"
              className="flex items-center space-x-3"
            >
              <div className="w-8 h-8 bg-black dark:bg-white rounded-full flex items-center justify-center">
                <span className="text-white dark:text-black text-sm font-medium">
                  {(user.fullName || user.email || 'U').charAt(0).toUpperCase()}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-black dark:text-white truncate">
                  {user.fullName || user.email}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                  {user.email}
                </p>
              </div>
            </motion.div>
          )}

          {/* Theme toggle */}
          <div className={`flex items-center ${isCollapsed ? 'justify-center' : 'justify-between'}`}>
            <TooltipProvider delayDuration={0}>
              <Tooltip>
                <TooltipTrigger asChild>
                  <div className={`flex items-center space-x-2 ${isCollapsed ? 'justify-center' : ''}`}>
                    <Sun className="w-4 h-4 text-gray-500 dark:text-gray-400" />
                    <Switch
                      checked={isDarkMode}
                      onCheckedChange={setIsDarkMode}
                      className="scale-75"
                    />
                    <Moon className="w-4 h-4 text-gray-500 dark:text-gray-400" />
                  </div>
                </TooltipTrigger>
                {isCollapsed && (
                  <TooltipContent side="right" className="ml-2">
                    <p>Toggle theme</p>
                  </TooltipContent>
                )}
              </Tooltip>
            </TooltipProvider>
          </div>

          <TooltipProvider delayDuration={0}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="outline"
                  onClick={handleLogout}
                  className={`w-full ${isCollapsed ? 'justify-center px-2' : 'justify-start'} text-gray-600 hover:text-black dark:text-gray-400 dark:hover:text-white border-gray-200 dark:border-gray-800`}
                >
                  <LogOut className="w-4 h-4" />
                  {!isCollapsed && (
                    <motion.span
                      variants={navItemVariants}
                      initial="collapsed"
                      animate="expanded"
                      className="ml-2"
                    >
                      Logout
                    </motion.span>
                  )}
                </Button>
              </TooltipTrigger>
              {isCollapsed && (
                <TooltipContent side="right" className="ml-2">
                  <p>Logout</p>
                </TooltipContent>
              )}
            </Tooltip>
          </TooltipProvider>
        </div>
      </motion.div>
    </>
  );
}