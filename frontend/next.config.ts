import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        // Ye poori site par apply hoga
        source: "/(.*)",
        headers: [
          {
            // Ye Chrome extensions ko tera Next.js app iframe me load karne ki permission dega
            key: "Content-Security-Policy",
            value: "frame-ancestors 'self' chrome-extension://*",
          },
        ],
      },
    ];
  },
};

export default nextConfig;