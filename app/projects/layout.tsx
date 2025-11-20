import { Metadata } from "next";
import ProjectsPage from "./page";

export const metadata: Metadata = {
  title: "API Console | Projects",
  description: "Gérez vos projets d'API - Créez, configurez et déployez vos endpoints et services",
};

export default function ProjectsLayout() {
  return <ProjectsPage />;
}