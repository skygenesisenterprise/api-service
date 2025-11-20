import { Metadata } from "next";
import ServicesPage from "./page";

export const metadata: Metadata = {
  title: "API Console | Services",
  description: "Hub de services - Connectez, configurez et surveillez toutes vos intégrations d'infrastructure",
};

export default function ServicesLayout() {
  return <ServicesPage />;
}