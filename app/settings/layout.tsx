import { Metadata } from "next";
import SettingsPageContent from "./page-content";

export const metadata: Metadata = {
  title: "API Console | Settings",
  description: "Configure your organization, workspace, security, and billing preferences",
};

export default function SettingsLayout() {
  return <SettingsPageContent />;
}