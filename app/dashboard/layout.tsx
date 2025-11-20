import { Metadata } from "next";
import DashboardPage from "./page";

export const metadata: Metadata = {
  title: "API Console | Dashboard",
  description: "Tableau de bord de l'API Console - Surveillez les métriques, l'état des services et les performances en temps réel",
};

export default function DashboardLayout() {
  return <DashboardPage />;
}