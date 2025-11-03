"use client";

import { NAVIGATION_MODE, isFreeNavigationEnabled } from '../lib/navigation-config';

export const NavigationModeIndicator: React.FC = () => {
  const isDevelopment = isFreeNavigationEnabled();
  
  return (
    <div className={`fixed top-4 right-4 z-50 px-3 py-1 rounded-full text-xs font-medium ${
      isDevelopment 
        ? 'bg-green-100 text-green-800 border border-green-200' 
        : 'bg-red-100 text-red-800 border border-red-200'
    }`}>
      {isDevelopment ? '🛠️ Development Mode' : '🔒 Production Mode'}
    </div>
  );
};

export const NavigationModeInfo: React.FC = () => {
  const isDevelopment = isFreeNavigationEnabled();
  
  return (
    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
      <h3 className="text-sm font-medium text-blue-800 mb-2">
        Mode de navigation actuel: {isDevelopment ? 'Développement' : 'Production'}
      </h3>
      <div className="text-xs text-blue-700">
        {isDevelopment ? (
          <p>
            <strong>Navigation libre:</strong> Toutes les pages sont accessibles sans authentification.
            Idéal pour le développement et les tests.
          </p>
        ) : (
          <p>
            <strong>Navigation sécurisée:</strong> L'authentification est requise pour les routes protégées.
            Les utilisateurs doivent se connecter pour accéder au tableau de bord et autres fonctionnalités.
          </p>
        )}
      </div>
      <div className="mt-2 text-xs text-blue-600">
        <p>Variable d'environnement: <code>NEXT_PUBLIC_NAVIGATION_MODE={NAVIGATION_MODE}</code></p>
      </div>
    </div>
  );
};