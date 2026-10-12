import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CounterFlow Control Center",
  description: "Live security telemetry and incident response for the CounterFlow authorized lab.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
