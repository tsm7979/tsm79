import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'TSM — AI Firewall',
  description: 'Real-time observability for your AI traffic',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
