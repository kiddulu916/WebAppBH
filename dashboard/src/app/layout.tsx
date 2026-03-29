import type { Metadata } from "next";
import localFont from "next/font/local";
import { Toaster } from "sonner";
import IconRail from "@/components/layout/IconRail";
import TopBar from "@/components/layout/TopBar";
import FooterBar from "@/components/layout/FooterBar";
import BottomDock from "@/components/layout/BottomDock";
import CommandPalette from "@/components/layout/CommandPalette";
import ShortcutsOverlay from "@/components/layout/ShortcutsOverlay";
import SystemCheck from "@/components/common/SystemCheck";
import GlobalEventStream from "@/components/common/GlobalEventStream";
import OnboardingTour from "@/components/common/OnboardingTour";
import "./globals.css";

const geistSans = localFont({
  src: "./fonts/GeistVF.woff2",
  variable: "--font-geist-sans",
  weight: "100 900",
});
const geistMono = localFont({
  src: "./fonts/GeistMonoVF.woff2",
  variable: "--font-geist-mono",
  weight: "100 900",
});

export const metadata: Metadata = {
  title: "WebAppBH \u2014 C2 Dashboard",
  description: "Bug Bounty Framework Command & Control",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-bg-void text-text-primary`}
      >
        <SystemCheck>
          <GlobalEventStream />
          <div className="flex min-h-screen min-w-[1024px]">
            <IconRail />
            <div className="ml-12 flex flex-1 flex-col min-h-screen">
              <TopBar />
              <main className="flex-1 overflow-auto p-4">{children}</main>
              <BottomDock />
              <FooterBar />
            </div>
          </div>
          <CommandPalette />
          <ShortcutsOverlay />
          <OnboardingTour />
        </SystemCheck>
        <Toaster
          theme="dark"
          position="top-right"
          toastOptions={{
            style: {
              background: "var(--bg-surface)",
              border: "1px solid var(--border)",
              color: "var(--text-primary)",
              fontSize: "12px",
            },
            duration: 3000,
          }}
        />
      </body>
    </html>
  );
}
