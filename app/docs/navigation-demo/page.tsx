"use client";

import { NavigationModeInfo } from '../../components/NavigationModeIndicator';
import { useNavigationAuth } from '../../hooks/useNavigationAuth';
import { ProtectedRoute } from '../../components/ProtectedRoute';


export default function NavigationDemoPage() {
  const { canAccessRoute, isDevelopmentMode } = useNavigationAuth();

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold text-gray-900 mb-8">
          Démonstration du Mode de Navigation
        </h1>

        <NavigationModeInfo />

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
            <h2 className="text-xl font-semibold mb-4">État Actuel</h2>
            <div className="space-y-2 text-sm">
              <p><strong>Mode:</strong> {isDevelopmentMode ? 'Développement' : 'Production'}</p>
              <p><strong>Navigation libre:</strong> {isDevelopmentMode ? 'Oui' : 'Non'}</p>
              <p><strong>Authentification requise:</strong> {!isDevelopmentMode ? 'Oui (pour routes protégées)' : 'Non'}</p>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
            <h2 className="text-xl font-semibold mb-4">Test d'accès aux routes</h2>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span>/dashboard:</span>
                <span className={canAccessRoute('/dashboard') ? 'text-green-600' : 'text-red-600'}>
                  {canAccessRoute('/dashboard') ? 'Accessible' : 'Bloqué'}
                </span>
              </div>
              <div className="flex justify-between">
                <span>/projects:</span>
                <span className={canAccessRoute('/projects') ? 'text-green-600' : 'text-red-600'}>
                  {canAccessRoute('/projects') ? 'Accessible' : 'Bloqué'}
                </span>
              </div>
              <div className="flex justify-between">
                <span>/login:</span>
                <span className={canAccessRoute('/login') ? 'text-green-600' : 'text-red-600'}>
                  {canAccessRoute('/login') ? 'Accessible' : 'Bloqué'}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
            <h2 className="text-xl font-semibold mb-4">Contenu Public</h2>
            <p className="text-gray-600">
              Ce contenu est visible dans tous les modes car il se trouve dans une route publique.
            </p>
          </div>

          <ProtectedRoute fallback={
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4 text-yellow-800">Contenu Protégé</h2>
              <p className="text-yellow-700">
                Ce contenu nécessite une authentification en mode production.
                En mode développement, il est directement accessible.
              </p>
            </div>
          }>
            <div className="bg-green-50 border border-green-200 rounded-lg p-6">
              <h2 className="text-xl font-semibold mb-4 text-green-800">Contenu Protégé - Accès Autorisé</h2>
              <p className="text-green-700">
                Félicitations! Vous avez accès à ce contenu protégé.
                {isDevelopmentMode && ' (Mode développement: accès automatique)'}
                {!isDevelopmentMode && ' (Mode production: authentification requise)'}
              </p>
            </div>
          </ProtectedRoute>
        </div>

        <div className="mt-8 bg-gray-50 p-6 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Comment changer le mode</h2>
          <div className="text-sm space-y-2">
            <p>Modifiez la variable d'environnement <code className="bg-gray-200 px-2 py-1 rounded">NEXT_PUBLIC_NAVIGATION_MODE</code> dans votre fichier <code className="bg-gray-200 px-2 py-1 rounded">.env</code>:</p>
            <div className="bg-white p-4 rounded border">
              <code>
                # Pour le développement<br/>
                NEXT_PUBLIC_NAVIGATION_MODE=development<br/><br/>
                # Pour la production<br/>
                NEXT_PUBLIC_NAVIGATION_MODE=production
              </code>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}