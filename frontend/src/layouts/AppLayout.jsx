import { NavLink, Outlet, Link } from 'react-router-dom';

const links = [
  ['/dashboard', 'Dashboard'],
  ['/files', 'My Files'],
  ['/upload', 'Upload'],
  ['/shared', 'Shared with me'],
  ['/security', 'Security'],
  ['/audit', 'Audit log'],
  ['/profile', 'Profile'],
];

export default function AppLayout() {
  return (
    <>
      <nav className="navbar navbar-dark bg-dark">
        <div className="container-fluid">
          <Link to="/dashboard" className="navbar-brand">Adaptive Secure Cloud</Link>
          <Link to="/login" className="btn btn-outline-light btn-sm">Sign out</Link>
        </div>
      </nav>

      <div className="container-fluid">
        <div className="row">
          {/* Sidebar becomes a horizontal wrapping menu on small screens */}
          <aside className="col-md-3 col-lg-2 bg-body-tertiary border-end py-3 min-vh-md-100">
            <ul className="nav flex-md-column nav-pills gap-1 px-2">
              {links.map(([to, label]) => (
                <li className="nav-item" key={to}>
                  <NavLink to={to} className={({ isActive }) => `nav-link ${isActive ? 'active' : 'text-dark'}`}>
                    {label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </aside>
          <main className="col-md-9 col-lg-10 py-4 px-md-4">
            <Outlet />
          </main>
        </div>
      </div>
    </>
  );
}