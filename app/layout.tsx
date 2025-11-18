"use client";

import { Geist, Geist_Mono } from "next/font/google";
import "./styles/globals.css";
import { AuthProvider } from "./context/JwtAuthContext";
import { SidebarProvider } from "./context/SidebarContext";
import { Toaster } from "./components/ui/toaster";
import { NavigationModeIndicator } from "./components/NavigationModeIndicator";
import { Sidebar } from "./components/ui/sidebar";
import { Header } from "./components/ui/header";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="fr">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <AuthProvider>
          <SidebarProvider>
            <div className="flex h-screen relative overflow-hidden bg-black">
              {/* Animated background pattern */}
              <div className="absolute inset-0 opacity-10 z-0">
                <div
                  className="absolute inset-0"
                  style={{
                    backgroundImage: `radial-gradient(circle at 2px 2px, white 1px, transparent 0)`,
                    backgroundSize: "40px 40px",
                  }}
                />
              </div>

              {/* Animated gradient orbs */}
              <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-white/5 rounded-full blur-3xl animate-pulse z-0" />
              <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-white/5 rounded-full blur-3xl animate-pulse delay-1000 z-0" />

              {/* Main content */}
              <div className="relative z-10 flex h-full w-full">
                <Sidebar />
                <div className="flex-1 flex flex-col">
                  <Header />
                  <div className="flex-1 flex flex-col overflow-hidden">
                    <NavigationModeIndicator />
                    <main className="flex-1 overflow-auto p-6">
                      {children}
                    </main>
                    <Toaster />
                  </div>
                </div>
              </div>
            </div>
          </SidebarProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
