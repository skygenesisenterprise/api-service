"use client";

import { motion } from "framer-motion";
import { Loader2, Save, Plus, Building2, Upload, Palette } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { Organization } from "../../types/settings";

interface GrafanaGeneralSectionProps {
  activeSection: string;
  organization: Organization;
  setOrganization: (updates: Partial<Organization>) => void;
  hasChanges: boolean;
  isSaving: boolean;
  handleSave: () => Promise<void>;
}

export function GrafanaGeneralSection({
  activeSection,
  organization,
  setOrganization,
  hasChanges,
  isSaving,
  handleSave,
}: GrafanaGeneralSectionProps) {
  
  const getSectionInfo = () => {
    switch (activeSection) {
      case "organization":
        return {
          title: "Organisation",
          description: "Gérez les informations de base de votre organisation",
          icon: Building2
        };
      case "workspace":
        return {
          title: "Espace de travail",
          description: "Configurez les préférences de votre espace de travail",
          icon: Building2
        };
      case "branding":
        return {
          title: "Identité visuelle",
          description: "Personnalisez l'apparence de votre espace de travail",
          icon: Palette
        };
      default:
        return {
          title: "Général",
          description: "Configuration générale",
          icon: Building2
        };
    }
  };

  const sectionInfo = getSectionInfo();
  const Icon = sectionInfo.icon;

  if (activeSection === "organization") {
    return (
      <motion.div 
        className="space-y-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
              <Icon className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{sectionInfo.title}</h1>
              <p className="text-gray-600">{sectionInfo.description}</p>
            </div>
          </div>
        </div>

        {/* Organization Settings Card */}
        <motion.div
          whileHover={{ y: -2, boxShadow: "0 8px 25px -5px rgba(0, 0, 0, 0.1)" }}
          transition={{ duration: 0.2 }}
        >
          <Card className="border-gray-200">
            <CardHeader className="pb-4">
              <CardTitle className="text-lg">Paramètres de l'organisation</CardTitle>
              <CardDescription>
                Informations essentielles de votre organisation
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="org-name" className="text-sm font-medium text-gray-700">
                    Nom de l'organisation
                  </Label>
                  <Input
                    id="org-name"
                    value={organization.name}
                    onChange={(e) => setOrganization({ name: e.target.value })}
                    className="h-10"
                    placeholder="Nom de votre organisation"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="workspace-name" className="text-sm font-medium text-gray-700">
                    Nom de l'espace de travail
                  </Label>
                  <Input
                    id="workspace-name"
                    value={organization.workspaceName}
                    onChange={(e) => setOrganization({ workspaceName: e.target.value })}
                    className="h-10"
                    placeholder="Espace de travail principal"
                  />
                </div>
              </div>
              
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label htmlFor="timezone" className="text-sm font-medium text-gray-700">
                    Fuseau horaire par défaut
                  </Label>
                  <Select 
                    value={organization.timezone} 
                    onValueChange={(value) => setOrganization({ timezone: value })}
                  >
                    <SelectTrigger className="h-10">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="UTC">UTC</SelectItem>
                      <SelectItem value="America/New_York">America/New_York</SelectItem>
                      <SelectItem value="Europe/London">Europe/London</SelectItem>
                      <SelectItem value="Europe/Paris">Europe/Paris</SelectItem>
                      <SelectItem value="Asia/Tokyo">Asia/Tokyo</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="locale" className="text-sm font-medium text-gray-700">
                    Langue par défaut
                  </Label>
                  <Select 
                    value={organization.locale} 
                    onValueChange={(value) => setOrganization({ locale: value })}
                  >
                    <SelectTrigger className="h-10">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="en">English</SelectItem>
                      <SelectItem value="fr">Français</SelectItem>
                      <SelectItem value="de">Deutsch</SelectItem>
                      <SelectItem value="es">Español</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex justify-end pt-4">
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Button 
                    onClick={handleSave}
                    disabled={!hasChanges || isSaving}
                    className="bg-blue-600 hover:bg-blue-700 px-6"
                    size="sm"
                  >
                    {isSaving ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Enregistrement...
                      </>
                    ) : (
                      <>
                        <Save className="w-4 h-4 mr-2" />
                        Enregistrer les modifications
                      </>
                    )}
                  </Button>
                </motion.div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    );
  }

  if (activeSection === "branding") {
    return (
      <motion.div 
        className="space-y-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center">
              <Icon className="w-5 h-5 text-purple-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{sectionInfo.title}</h1>
              <p className="text-gray-600">{sectionInfo.description}</p>
            </div>
          </div>
        </div>

        {/* Branding Card */}
        <motion.div
          whileHover={{ y: -2, boxShadow: "0 8px 25px -5px rgba(0, 0, 0, 0.1)" }}
          transition={{ duration: 0.2 }}
        >
          <Card className="border-gray-200">
            <CardHeader className="pb-4">
              <CardTitle className="text-lg">Options de personnalisation</CardTitle>
              <CardDescription>
                Personnalisez l'apparence de votre espace de travail
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-8">
              {/* Logo Upload */}
              <div className="space-y-4">
                <Label className="text-sm font-medium text-gray-700">Logo de l'organisation</Label>
                <div className="flex items-center gap-6">
                  <motion.div 
                    className="w-24 h-24 bg-gray-50 border-2 border-dashed border-gray-300 rounded-xl flex items-center justify-center"
                    whileHover={{ scale: 1.05, borderColor: "#3b82f6" }}
                    transition={{ duration: 0.2 }}
                  >
                    <Building2 className="w-10 h-10 text-gray-400" />
                  </motion.div>
                  <div className="space-y-3">
                    <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                      <Button variant="outline" className="flex items-center gap-2">
                        <Upload className="w-4 h-4" />
                        Télécharger le logo
                      </Button>
                    </motion.div>
                    <p className="text-xs text-gray-500">
                      PNG, JPG ou GIF. Taille maximale 2MB. Recommandé 256x256px.
                    </p>
                  </div>
                </div>
              </div>

              {/* Accent Color */}
              <div className="space-y-4">
                <Label className="text-sm font-medium text-gray-700">Couleur d'accent</Label>
                <div className="flex items-center gap-4">
                  <motion.div
                    className="relative"
                    whileHover={{ scale: 1.05 }}
                    transition={{ duration: 0.2 }}
                  >
                    <Input
                      id="accent-color"
                      type="color"
                      value={organization.accentColor}
                      onChange={(e) => setOrganization({ accentColor: e.target.value })}
                      className="w-16 h-16 rounded-lg cursor-pointer border-2 border-gray-200"
                    />
                  </motion.div>
                  <div className="flex-1">
                    <Input
                      value={organization.accentColor}
                      onChange={(e) => setOrganization({ accentColor: e.target.value })}
                      placeholder="#3b82f6"
                      className="h-10 font-mono"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Code hexadécimal de la couleur principale
                    </p>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-4">
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Button 
                    onClick={handleSave}
                    disabled={!hasChanges || isSaving}
                    className="bg-blue-600 hover:bg-blue-700 px-6"
                    size="sm"
                  >
                    {isSaving ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Enregistrement...
                      </>
                    ) : (
                      <>
                        <Save className="w-4 h-4 mr-2" />
                        Enregistrer les modifications
                      </>
                    )}
                  </Button>
                </motion.div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    );
  }

  if (activeSection === "workspace") {
    return (
      <motion.div 
        className="space-y-6"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
      >
        {/* Header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
              <Icon className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{sectionInfo.title}</h1>
              <p className="text-gray-600">{sectionInfo.description}</p>
            </div>
          </div>
        </div>

        {/* Workspace Settings Card */}
        <motion.div
          whileHover={{ y: -2, boxShadow: "0 8px 25px -5px rgba(0, 0, 0, 0.1)" }}
          transition={{ duration: 0.2 }}
        >
          <Card className="border-gray-200">
            <CardHeader className="pb-4">
              <CardTitle className="text-lg">Paramètres de l'espace de travail</CardTitle>
              <CardDescription>
                Configurez les préférences de votre espace de travail
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <Label htmlFor="workspace-description" className="text-sm font-medium text-gray-700">
                  Description de l'espace de travail
                </Label>
                <textarea
                  id="workspace-description"
                  className="w-full p-3 border border-gray-300 rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                  rows={4}
                  placeholder="Décrivez votre espace de travail..."
                />
              </div>

              <div className="flex justify-end pt-4">
                <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }}>
                  <Button 
                    onClick={handleSave}
                    disabled={!hasChanges || isSaving}
                    className="bg-blue-600 hover:bg-blue-700 px-6"
                    size="sm"
                  >
                    {isSaving ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Enregistrement...
                      </>
                    ) : (
                      <>
                        <Save className="w-4 h-4 mr-2" />
                        Enregistrer les modifications
                      </>
                    )}
                  </Button>
                </motion.div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </motion.div>
    );
  }

  return null;
}