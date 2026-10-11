import React from 'react';

interface SpiderLogoProps {
  className?: string;
  size?: number;
  showGlow?: boolean;
}

export const SpiderLogo: React.FC<SpiderLogoProps> = ({
  className = 'w-8 h-8',
  size,
  showGlow = true,
}) => {
  const style = size ? { width: size, height: size } : undefined;

  return (
    <div
      style={style}
      className={`relative inline-flex items-center justify-center shrink-0 ${className}`}
    >
      {showGlow && (
        <div className="absolute inset-0 rounded-full bg-emerald-500/20 blur-md pointer-events-none scale-110" />
      )}
      <img
        src="/spider-logo.svg"
        alt="SPIDER Logo"
        className="relative z-10 w-full h-full object-contain filter drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]"
      />
    </div>
  );
};
