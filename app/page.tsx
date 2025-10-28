"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuthContext } from "@/app/context/AuthContext";

export default function Home() {
  const { isAuthenticated } = useAuthContext();
  const router = useRouter();

  useEffect(() => {
    if (isAuthenticated) router.replace("/pages/admin");
    else router.replace("/pages/auth/login");
  }, [isAuthenticated, router]);

  return null;
}
