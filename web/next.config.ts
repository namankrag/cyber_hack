import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  async headers() {
    // Browser-facing hardening. The JSON gateway sets its own headers
    // (see agentshield/gateway/app.py); these cover the console pages and
    // the /api proxy responses. No script-src CSP: Next.js hydration needs
    // inline scripts, and a half-CSP is worse than none.
    const security = [
      { key: "X-Content-Type-Options", value: "nosniff" },
      { key: "X-Frame-Options", value: "DENY" },
      { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
      {
        key: "Permissions-Policy",
        value: "camera=(), microphone=(), geolocation=()",
      },
    ];
    return [
      { source: "/workspace/:path*", headers: security },
      { source: "/api/:path*", headers: security },
    ];
  },
  experimental: {
    optimizePackageImports: ["lucide-react"],
  },
};

export default nextConfig;
