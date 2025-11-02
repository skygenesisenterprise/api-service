"use client";

import React, { createContext, useContext, useMemo } from "react";
import { useSession, signIn, signOut } from "next-auth/react";

interface IAuthContext {
  token: string | null;
  isAuthenticated: boolean;
  user: any;
  login: () => void;
  logout: () => void;
  signInWithKeycloak: () => void;
}

const AuthContext = createContext<IAuthContext | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { data: session, status } = useSession();

  const login = () => {
    // For backward compatibility - can be removed if not needed
  };

  const logout = () => {
    signOut({ callbackUrl: '/login' });
  };

  const signInWithKeycloak = () => {
    signIn('keycloak', { callbackUrl: '/' });
  };

  const value = useMemo<IAuthContext>(() => ({
    token: session?.accessToken || null,
    isAuthenticated: !!session,
    user: session?.user,
    login,
    logout,
    signInWithKeycloak,
  }), [session]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuthContext(): IAuthContext {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuthContext must be used within AuthProvider");
  return ctx;
}


