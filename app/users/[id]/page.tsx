"use client";

import { useState, useEffect } from "react";
import { useParams, useRouter } from "next/navigation";

import DashboardPageLayout from "../../components/DashboardPageLayout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Badge } from "../../components/ui/badge";
import { 
  ArrowLeft, 
  Edit, 
  Mail, 
  Calendar, 
  Shield, 
  User,
  Activity,
  Clock
} from "lucide-react";

interface UserDetails {
  id: string;
  name: string;
  email: string;
  role: string;
  status: 'active' | 'inactive' | 'suspended';
  createdAt: string;
  lastLogin?: string;
  phone?: string;
  department?: string;
  location?: string;
  avatar?: string;
}

export default function UserDetailPage() {
  
  const params = useParams();
  const router = useRouter();
  const [user, setUser] = useState<UserDetails | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Simulate loading user data
    const loadUser = async () => {
      setLoading(true);
      try {
        // In a real implementation, this would fetch from API
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const mockUser: UserDetails = {
          id: params.id as string,
          name: "Jean Dupont",
          email: "jean.dupont@example.com",
          role: "Admin",
          status: "active",
          createdAt: "2024-01-15",
          lastLogin: "2024-03-10T14:30:00Z",
          phone: "+33 6 12 34 56 78",
          department: "IT",
          location: "Paris, France",
          avatar: undefined
        };
        
        setUser(mockUser);
      } catch (error) {
        console.error('Failed to load user:', error);
      } finally {
        setLoading(false);
      }
    };

    if (params.id) {
      loadUser();
    }
  }, [params.id]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800';
      case 'inactive':
        return 'bg-gray-100 text-gray-800';
      case 'suspended':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'Admin':
        return 'bg-purple-100 text-purple-800';
      case 'Manager':
        return 'bg-blue-100 text-blue-800';
      case 'User':
        return 'bg-gray-100 text-gray-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('fr-FR', {
      day: 'numeric',
      month: 'long',
      year: 'numeric'
    });
  };

  const formatLastLogin = (dateString?: string) => {
    if (!dateString) return 'Jamais';
    const date = new Date(dateString);
    const now = new Date();
    const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
    
    if (diffInHours < 1) return 'Moins d\'une heure';
    if (diffInHours < 24) return `Il y a ${diffInHours} heures`;
    if (diffInHours < 48) return 'Hier';
    return formatDate(dateString);
  };

  if (loading) {
    return (
      <DashboardPageLayout title="Détails de l'utilisateur" subtitle="Informations détaillées">
        <div className="space-y-6">
          <div className="animate-pulse">
            <div className="h-96 bg-gray-200 rounded"></div>
          </div>
        </div>
      </DashboardPageLayout>
    );
  }

  if (!user) {
    return (
      <DashboardPageLayout title="Utilisateur non trouvé" subtitle="">
        <div className="text-center py-12">
          <p className="text-gray-500 mb-4">L'utilisateur demandé n'a pas été trouvé.</p>
          <Button onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Retour
          </Button>
        </div>
      </DashboardPageLayout>
    );
  }

  return (
    <DashboardPageLayout title={user.name} subtitle="Détails de l'utilisateur">
      <div className="space-y-6">
        {/* Back Button */}
        <Button
          variant="outline"
          onClick={() => router.back()}
        >
          <ArrowLeft className="h-4 w-4 mr-2" />
          Retour
        </Button>

        {/* User Info Card */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="w-16 h-16 bg-gray-300 rounded-full flex items-center justify-center">
                  <User className="w-8 h-8 text-gray-600" />
                </div>
                <div>
                  <CardTitle className="text-2xl">{user.name}</CardTitle>
                  <CardDescription className="text-lg">{user.email}</CardDescription>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Badge className={getRoleColor(user.role)}>
                  {user.role === 'Admin' ? 'Administrateur' : 
                   user.role === 'Manager' ? 'Manager' : 'Utilisateur'}
                </Badge>
                <Badge className={getStatusColor(user.status)}>
                  {user.status === 'active' ? 'Actif' : 
                   user.status === 'inactive' ? 'Inactif' : 'Suspendu'}
                </Badge>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex justify-end">
              <Button onClick={() => router.push(`/users/${user.id}/edit`)}>
                <Edit className="h-4 w-4 mr-2" />
                Modifier
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Details Grid */}
        <div className="grid gap-6 md:grid-cols-2">
          {/* Personal Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                Informations personnelles
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">Nom complet</span>
                <span className="font-medium">{user.name}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">Email</span>
                <span className="font-medium">{user.email}</span>
              </div>
              {user.phone && (
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Téléphone</span>
                  <span className="font-medium">{user.phone}</span>
                </div>
              )}
              {user.department && (
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Département</span>
                  <span className="font-medium">{user.department}</span>
                </div>
              )}
              {user.location && (
                <div className="flex justify-between">
                  <span className="text-sm text-gray-500">Localisation</span>
                  <span className="font-medium">{user.location}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Account Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Informations du compte
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">Rôle</span>
                <Badge className={getRoleColor(user.role)}>
                  {user.role === 'Admin' ? 'Administrateur' : 
                   user.role === 'Manager' ? 'Manager' : 'Utilisateur'}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">Statut</span>
                <Badge className={getStatusColor(user.status)}>
                  {user.status === 'active' ? 'Actif' : 
                   user.status === 'inactive' ? 'Inactif' : 'Suspendu'}
                </Badge>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">ID Utilisateur</span>
                <span className="font-medium font-mono text-sm">{user.id}</span>
              </div>
            </CardContent>
          </Card>

          {/* Activity Information */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                Activité
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">Dernière connexion</span>
                <span className="font-medium">{formatLastLogin(user.lastLogin)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-gray-500">Date de création</span>
                <span className="font-medium">{formatDate(user.createdAt)}</span>
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Actions rapides
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button variant="outline" className="w-full justify-start">
                <Mail className="h-4 w-4 mr-2" />
                Envoyer un email
              </Button>
              <Button variant="outline" className="w-full justify-start">
                <Shield className="h-4 w-4 mr-2" />
                Réinitialiser le mot de passe
              </Button>
              <Button variant="outline" className="w-full justify-start">
                <Calendar className="h-4 w-4 mr-2" />
                Voir l'historique
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardPageLayout>
  );
}