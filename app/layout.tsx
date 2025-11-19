"use client";

import { Geist, Geist_Mono } from "next/font/google";
import "./styles/globals.css";
import { AuthProvider } from "./context/JwtAuthContext";
import { AuthProvider as UnifiedAuthProvider } from "./context/UnifiedAuthContext";
import { ProtectedLayout } from "./components/ui/ProtectedLayout";

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
          <UnifiedAuthProvider>
            <ProtectedLayout>{children}</ProtectedLayout>
          </UnifiedAuthProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
