
const RULES = [
  {
    title: 'Client-side encryption',
    level: 'ENFORCED',
    color: 'success',
    description:
      'Files are encrypted in the browser using AES-256-GCM before they are uploaded.'
  },
  {
    title: 'Content-aware inspection',
    level: 'INSPECTION',
    color: 'info',
    description:
      'Supported files are inspected locally for sensitive information before encryption. Only sanitized indicators are sent to the backend.'
  },
  {
    title: 'User sensitivity protection',
    level: 'ENFORCED',
    color: 'success',
    description:
      'User-declared sensitivity contributes to risk classification. Higher sensitivity cannot be reduced by a lower declaration.'
  },
  {
    title: 'Step-up verification',
    level: 'ENFORCED',
    color: 'success',
    description:
      'HIGH and CRITICAL file access requires additional verification under the existing security policy.'
  },
  {
    title: 'Risk-aware file sharing',
    level: 'POLICY',
    color: 'primary',
    description:
      'File sharing is subject to the existing risk-based sharing restrictions and limits.'
  },
  {
    title: 'Inspection failure handling',
    level: 'REVIEW',
    color: 'warning',
    description:
      'Unsupported or failed inspections should be reviewed. Do not interpret missing inspection evidence as proof that a file is safe.'
  }
];

export default function SecurityRulesPanel() {
  return (
    <div className="card shadow-sm mt-4">
      <div className="card-header fw-semibold d-flex justify-content-between align-items-center">
        <span>Security Rules & Policies</span>
        <span className="badge bg-dark">6 Rules</span>
      </div>

      <div className="card-body">
        <p className="text-muted small mb-3">
          Security controls applied by the Adaptive Secure Cloud system.
        </p>

        <div className="row g-3">
          {RULES.map((rule, index) => (
            <div className="col-md-6" key={rule.title}>
              <div className="border rounded p-3 h-100">
                <div className="d-flex justify-content-between align-items-start gap-2 mb-2">
                  <span className="fw-semibold">
                    {index + 1}. {rule.title}
                  </span>
                  <span className={`badge bg-${rule.color}`}>
                    {rule.level}
                  </span>
                </div>

                <p className="small text-muted mb-0">
                  {rule.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
