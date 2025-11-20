import { Metadata } from "next";
import MonitoringPage from "./page";

export const metadata: Metadata = {
  title: "API Console | Requests Monitoring",
  description: "Surveillance des requêtes API - Analysez les performances, les erreurs et les tendances en temps réel",
};

export default function MonitoringLayout() {
  return <MonitoringPage />;
}