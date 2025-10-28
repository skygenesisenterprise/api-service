"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

interface IAuthContext {
  token: string | null;
  isAuthenticated: boolean;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = createContext<IAuthContext | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    try {
      const existing = typeof window !== "undefined" ? localStorage.getItem("sge_token") : null;
      if (existing) setToken(existing);
    } catch (_) {
      // ignore
    }
  }, []);

  const login = useCallback((newToken: string) => {
    setToken(newToken);
    try {
      localStorage.setItem("sge_token", newToken);
    } catch (_) {
      // ignore
    }
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    try {
      localStorage.removeItem("sge_token");
    } catch (_) {
      // ignore
    }
  }, []);

  const value = useMemo<IAuthContext>(() => ({ token, isAuthenticated: !!token, login, logout }), [token, login, logout]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuthContext(): IAuthContext {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuthContext must be used within AuthProvider");
  return ctx;
}


