import { Metadata } from "next";
import EndpointsPage from "./page";

export const metadata: Metadata = {
  title: "API Console | Endpoints",
  description: "Gérez vos endpoints API - Configurez, surveillez et analysez les performances de vos routes",
};

export default function EndpointsLayout() {
  return <EndpointsPage />;
}