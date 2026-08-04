import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { HeroSection } from './components/HeroSection';
import { InteractiveTerminal } from './components/InteractiveTerminal';
import { DecompilerDiff } from './components/DecompilerDiff';
import { HubMarketplace } from './components/HubMarketplace';
import { PricingTable } from './components/PricingTable';
import { SupabaseAuthModal } from './components/SupabaseAuthModal';
import { Footer } from './components/Footer';
import type { UserAuth } from './types';

export const App: React.FC = () => {
  const [auth, setAuth] = useState<UserAuth>({
    isLoggedIn: false,
  });

  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);

  useEffect(() => {
    const savedStatus = localStorage.getItem('openreverse_auth_status');
    const savedProvider = localStorage.getItem('openreverse_auth_provider') as 'GitHub' | 'Google';
    if (savedStatus === 'logged_in') {
      setAuth({
        isLoggedIn: true,
        provider: savedProvider || 'GitHub',
         username: 'Demo User',
         email: '',
         tier: 'COMMUNITY_FREE',
         licenseToken: '',
      });
    }
  }, []);

  const handleLogin = (provider: 'GitHub' | 'Google') => {
    const userAuth: UserAuth = {
      isLoggedIn: true,
      provider,
       username: 'Demo User',
       email: '',
       tier: 'COMMUNITY_FREE',
       licenseToken: '',
    };
    setAuth(userAuth);
    localStorage.setItem('openreverse_auth_status', 'logged_in');
    localStorage.setItem('openreverse_auth_provider', provider);
  };

  const handleLogout = () => {
    setAuth({ isLoggedIn: false });
    localStorage.removeItem('openreverse_auth_status');
    localStorage.removeItem('openreverse_auth_provider');
  };

  const scrollToTerminal = () => {
    const el = document.getElementById('AI-assisted-shell');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="min-h-screen bg-black text-[#fafafa] relative overflow-hidden">
      {/* Background Subtle Grid Pattern */}
      <div className="bg-grid-pattern" />

      {/* Navigation Bar */}
      <Navbar
        auth={auth}
        onOpenAuthModal={() => setIsAuthModalOpen(true)}
      />

      {/* Main Sections */}
      <main className="relative z-10">
        <HeroSection
          onScrollToTerminal={scrollToTerminal}
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
        />

        <InteractiveTerminal />

        <DecompilerDiff />

        <HubMarketplace />

        <PricingTable
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
        />
      </main>

      {/* Footer */}
      <Footer
        onOpenAuthModal={() => setIsAuthModalOpen(true)}
      />

      {/* Supabase OAuth Modal */}
      <SupabaseAuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        auth={auth}
        onLogin={handleLogin}
        onLogout={handleLogout}
      />
    </div>
  );
};

export default App;
