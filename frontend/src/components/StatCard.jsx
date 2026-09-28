export default function StatCard({ label, value, hint }) {
  return (
    <div className="card h-100 shadow-sm">
      <div className="card-body">
        <div className="text-muted small text-uppercase">{label}</div>
        <div className="fs-2 fw-semibold">{value}</div>
        {hint && <div className="text-muted small">{hint}</div>}
      </div>
    </div>
  );
}