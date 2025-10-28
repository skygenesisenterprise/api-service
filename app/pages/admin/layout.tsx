"use client";

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthContext } from "@/app/context/AuthContext";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    if (!isAuthenticated) {
      router.replace("/pages/auth/login");
    }
  }, [isAuthenticated, router]);

  if (!isAuthenticated) return null;

  return (
    <div className="min-h-screen bg-gray-50">
      <aside className="fixed left-0 top-0 h-full w-64 bg-white border-r">
        <div className="p-4 font-bold">SGE Admin</div>
        <nav className="p-2 space-y-1">
          <a className="block px-4 py-2 hover:bg-gray-100" href="/pages/admin">Dashboard</a>
          <a className="block px-4 py-2 hover:bg-gray-100" href="/pages/inbox">Inbox</a>
          <a className="block px-4 py-2 hover:bg-gray-100" href="/pages/profile">Profil</a>
          <a className="block px-4 py-2 hover:bg-gray-100" href="/pages/logs">Logs</a>
          <a className="block px-4 py-2 hover:bg-gray-100" href="/pages/settings/general">Paramètres</a>
        </nav>
      </aside>
      <main className="ml-64 p-6">{children}</main>
    </div>
  );
}


