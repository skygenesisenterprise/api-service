import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable React strict mode for better development experience
  reactStrictMode: true,

  // Remove X-Powered-By header for security
  poweredByHeader: false,

  // Standalone output for containerized deployments
  output: 'standalone',

  // Image optimization settings
  images: {
    // Add domains if using external images
    domains: [],
    // Enable image optimization
    unoptimized: false,
  },

  // Turbopack configuration (empty to silence webpack warning)
  turbopack: {},

  // Security headers
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'origin-when-cross-origin',
          },
        ],
      },
    ];
  },

  // Webpack configuration for custom builds
  webpack: (config, { dev, isServer }) => {
    // Add any custom webpack config here if needed
    return config;
  },
};

export default nextConfig;
