export function Escudo({ tamano = 28 }: { tamano?: number }) {
  return (
    <svg width={tamano} height={tamano} viewBox="0 0 32 32" aria-hidden>
      <path fill="#2f6fd6" d="M16 2 4 6.5v8.6C4 22.6 9.1 28.6 16 30c6.9-1.4 12-7.4 12-14.9V6.5z" />
      <path fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" d="m10.5 16.2 3.8 3.8 7.4-7.6" />
    </svg>
  );
}
