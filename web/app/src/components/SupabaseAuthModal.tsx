import React, { useState } from 'react';
import { X, Copy, Check, Globe, Key } from 'lucide-react';
import type { UserAuth } from '../types';

interface SupabaseAuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  auth: UserAuth;
  onLogin: (provider: 'GitHub' | 'Google') => void;
  onLogout: () => void;
}

export const SupabaseAuthModal: React.FC<SupabaseAuthModalProps> = ({
  isOpen,
  onClose,
  auth,
  onLogin,
  onLogout,
}) => {
  const [copied, setCopied] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  if (!isOpen) return null;

  const handleOAuthClick = (provider: 'GitHub' | 'Google') => {
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
      onLogin(provider);
    }, 700);
  };

  const handleCopyToken = () => {
    if (!auth.licenseToken) return;
    navigator.clipboard.writeText(auth.licenseToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div
      onClick={onClose}
      className="fixed inset-0 bg-black/85 backdrop-blur-sm z-[2000] flex items-center justify-center p-6 animate-fade-in"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md bg-[#09090b] border border-[#27272a] rounded-xl p-8 relative shadow-2xl shadow-black"
      >
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-[#71717a] hover:text-white transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="text-center mb-8">
          <div className="w-10 h-10 rounded-lg bg-[#18181b] border border-[#27272a] flex items-center justify-center text-white mx-auto mb-4">
            <Key className="w-5 h-5" />
          </div>
          <h3 className="text-xl font-bold text-white mb-1">
            {auth.isLoggedIn ? 'OpenReverse Cloud Studio Account' : 'Sign in to OpenReverse Cloud'}
          </h3>
          <p className="text-xs text-[#a1a1aa]">
            Powered by <strong>Supabase Auth</strong>. Seamless OAuth SSO with zero passwords.
          </p>
        </div>

        {!auth.isLoggedIn ? (
          <div className="space-y-3 mb-6">
            <button
              onClick={() => handleOAuthClick('GitHub')}
              disabled={isLoading}
              className="btn btn-secondary w-full py-3 justify-center text-sm font-mono"
            >
              <span>{isLoading ? 'Connecting to GitHub...' : 'Continue with GitHub'}</span>
            </button>

            <button
              onClick={() => handleOAuthClick('Google')}
              disabled={isLoading}
              className="btn btn-secondary w-full py-3 justify-center text-sm"
            >
              <Globe className="w-4 h-4" />
              <span>{isLoading ? 'Connecting to Google...' : 'Continue with Google'}</span>
            </button>
          </div>
        ) : (
          <div className="space-y-5 mb-6">
            {/* Logged in User Profile */}
            <div className="bg-[#121215] border border-[#27272a] rounded-lg p-4 flex items-center gap-4">
              <div className="w-12 h-12 rounded-full bg-gradient-to-tr from-emerald-500 to-teal-400 text-black font-extrabold text-sm flex items-center justify-center shadow-lg shadow-emerald-500/20">
                AF
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-white">{auth.username}</h4>
                  <span className="text-[10px] font-mono bg-emerald-500/15 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/30">
                    {auth.tier}
                  </span>
                </div>
                <span className="text-xs text-[#a1a1aa] block mt-0.5">{auth.email}</span>
                <div className="flex items-center gap-2 mt-2 text-[11px] text-[#71717a]">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  <span>EU-West (Paris • 14ms)</span>
                  <span>•</span>
                  <span>TLS 1.3 SSO</span>
                </div>
              </div>
            </div>

            {/* AI Decompiler Quota */}
            <div className="bg-[#121215] border border-[#27272a] rounded-lg p-3.5 space-y-2">
              <div className="flex justify-between items-center text-xs">
                <span className="text-[#a1a1aa] font-medium">AI Decompiler Monthly Quota</span>
                <span className="font-mono text-emerald-400 font-semibold">84% Remaining</span>
              </div>
              <div className="w-full bg-[#1e1e24] h-2 rounded-full overflow-hidden">
                <div className="bg-gradient-to-r from-emerald-500 to-teal-400 h-full w-[84%]" />
              </div>
              <div className="flex justify-between text-[10px] text-[#71717a] font-mono">
                <span>8,400 / 10,000 requests left</span>
                <span>Resets in 18 days</span>
              </div>
            </div>

            {/* License Token for Desktop App */}
            <div className="space-y-2">
              <label className="text-xs font-mono text-[#a1a1aa] block">
                Your OpenReverse Cloud Studio License Token:
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={auth.licenseToken}
                  readOnly
                  className="flex-1 bg-black/80 border border-[#27272a] rounded p-2.5 text-xs font-mono text-[#38bdf8] outline-none"
                />
                <button
                  onClick={handleCopyToken}
                  className="btn btn-primary text-xs py-2.5 px-4"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5" />
                      <span>Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <small className="text-[11px] text-[#71717a] block mt-1">
                In OpenReverse Studio, type: <code>/login {auth.licenseToken}</code> or sign in via GUI.
              </small>
            </div>

            <button
              onClick={onLogout}
              className="btn btn-ghost w-full py-2.5 text-xs text-[#f87171] hover:text-[#f87171] hover:bg-[#f87171]/10"
            >
              Sign Out
            </button>
          </div>
        )}

        <div className="text-center border-t border-[#27272a] pt-4">
          <span className="text-[11px] text-[#71717a]">
            By signing in, you agree to our Terms of Service &amp; Privacy Policy.
          </span>
        </div>
      </div>
    </div>
  );
};
