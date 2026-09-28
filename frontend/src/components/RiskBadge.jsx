const STYLES = {
  LOW: { className: 'text-bg-success' },
  MEDIUM: { className: 'text-bg-warning' },
  HIGH: { className: 'text-bg-danger-subtle text-danger-emphasis border border-danger-subtle', style: { backgroundColor: '#fd7e14', color: '#fff' } },
  CRITICAL: { className: 'text-bg-danger' },
};

export default function RiskBadge({ level }) {
  const s = STYLES[level] || { className: 'text-bg-secondary' };
  return (
    <span className={`badge ${s.className}`} style={s.style}>
      {level}
    </span>
  );
}