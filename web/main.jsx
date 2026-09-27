import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

const API = '/v1';

async function request(path, { method = 'GET', token, body } = {}) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body) headers['content-type'] = 'application/json';

  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    credentials: 'same-origin',
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let result = {};
  try {
    result = text ? JSON.parse(text) : {};
  } catch {
    throw new Error('The server returned an unreadable response.');
  }
  if (!response.ok) throw new Error(result.error?.message ?? 'The request failed.');
  return result;
}

function App() {
  const [token, setToken] = useState('');
  const [user, setUser] = useState(null);
  const [org, setOrg] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [permissions, setPermissions] = useState({});
  const [devices, setDevices] = useState([]);
  const [users, setUsers] = useState([]);
  const [grants, setGrants] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [events, setEvents] = useState([]);
  const [section, setSection] = useState('devices');
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [invite, setInvite] = useState(null);
  const [inviteAccepted, setInviteAccepted] = useState(false);
  const [grantForm, setGrantForm] = useState({ userId: '', deviceId: '', effect: 'allow', permissions: [] });

  const inviteMatch = window.location.pathname.match(/^\/invite\/([^/]+)$/);
  const inviteToken = inviteMatch?.[1];

  async function loadOrganization(accessToken, selectedOrg) {
    setError('');
    setDevices([]);
    setUsers([]);
    setGrants([]);
    setSessions([]);
    setEvents([]);

    const effective = await request(`/orgs/${selectedOrg.id}/effective`, { token: accessToken });
    const resolved = effective.permissions;
    setPermissions(resolved);

    if (resolved['device:list']?.effect === 'allow') {
      const result = await request(`/orgs/${selectedOrg.id}/devices`, { token: accessToken });
      setDevices(result.devices);
    }
    if (resolved['user:read']?.effect === 'allow') {
      const result = await request(`/orgs/${selectedOrg.id}/members`, { token: accessToken });
      setUsers(result.users);
    }
    if (resolved['user:read']?.effect === 'allow' || resolved['grant:create']?.effect === 'allow' || resolved['grant:revoke']?.effect === 'allow') {
      const result = await request(`/orgs/${selectedOrg.id}/grants`, { token: accessToken });
      setGrants(result.grants);
    }
    if (resolved['session:view']?.effect === 'allow') {
      const result = await request(`/orgs/${selectedOrg.id}/sessions`, { token: accessToken });
      setSessions(result.sessions);
    }
    if (resolved['audit:read']?.effect === 'allow') {
      const result = await request(`/orgs/${selectedOrg.id}/audit`, { token: accessToken });
      setEvents(result.events);
    }
  }

  useEffect(() => {
    if (inviteToken) {
      request(`/invites/${inviteToken}`).then(setInvite).catch((loadError) => setError(loadError.message));
      return;
    }

    request('/auth/refresh', { method: 'POST' })
      .then(async (session) => {
        setToken(session.token);
        setUser(session.user);
        setOrg(session.org);
        setOrgs(session.orgs);
        await loadOrganization(session.token, session.org);
      })
      .catch(() => {});
  }, []);

  async function handleLogin(event) {
    event.preventDefault();
    setError('');
    if (!email.trim() || !password) {
      setError('Enter your email and password.');
      return;
    }
    try {
      const session = await request('/auth/login', { method: 'POST', body: { email, password } });
      setToken(session.token);
      setUser(session.user);
      setOrg(session.org);
      setOrgs(session.orgs);
      setSection('devices');
      await loadOrganization(session.token, session.org);
    } catch (loginError) {
      setError(loginError.message);
    }
  }

  async function switchOrganization(nextOrgId) {
    setError('');
    try {
      const result = await request('/auth/token', { method: 'POST', token, body: { orgId: nextOrgId } });
      setToken(result.token);
      setOrg(result.org);
      await loadOrganization(result.token, result.org);
    } catch (switchError) {
      setError(switchError.message);
    }
  }

  async function createOrganization() {
    const name = window.prompt('Organization name');
    if (!name?.trim()) return;
    setError('');
    try {
      const created = await request('/orgs', { method: 'POST', token, body: { name } });
      const result = await request('/auth/token', { method: 'POST', token, body: { orgId: created.id } });
      const nextOrgs = [...orgs, { ...result.org, role: result.role }];
      setOrgs(nextOrgs);
      setToken(result.token);
      setOrg(result.org);
      setSection('devices');
      await loadOrganization(result.token, result.org);
    } catch (createError) {
      setError(createError.message);
    }
  }

  async function acceptInvite(event) {
    event.preventDefault();
    setError('');
    const form = new FormData(event.currentTarget);
    try {
      await request(`/invites/${inviteToken}/accept`, {
        method: 'POST',
        body: { name: form.get('name'), password: form.get('password') },
      });
      setEmail(invite.email);
      setInviteAccepted(true);
    } catch (acceptError) {
      setError(acceptError.message);
    }
  }

  async function createGrant(event) {
    event.preventDefault();
    setError('');
    try {
      await request(`/orgs/${org.id}/grants`, { method: 'POST', token, body: grantForm });
      await loadOrganization(token, org);
    } catch (grantError) {
      setError(grantError.message);
    }
  }

  async function openSection(nextSection) {
    setSection(nextSection);
    setError('');
    try {
      await loadOrganization(token, org);
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  if (inviteToken && !inviteAccepted) {
    if (!invite) {
      return <main><p data-testid="invite-error">{error || 'Loading invitation…'}</p></main>;
    }
    return (
      <main style={{ fontFamily: 'system-ui', maxWidth: 440, margin: '60px auto' }}>
        <h1>Join {invite.orgName}</h1>
        <p>Role: <span data-testid="invite-role">{invite.role}</span></p>
        <form onSubmit={acceptInvite}>
          <label>Email <input data-testid="invite-email" value={invite.email} readOnly /></label>
          <label>Name <input data-testid="invite-name" name="name" required /></label>
          <label>Password <input data-testid="invite-password" name="password" type="password" required /></label>
          <button data-testid="invite-submit" type="submit">Accept invitation</button>
        </form>
        {error && <p role="alert">{error}</p>}
      </main>
    );
  }

  if (!token) {
    return (
      <main style={{ fontFamily: 'system-ui', maxWidth: 400, margin: '80px auto', padding: 24 }}>
        <h1>RemoteOps</h1>
        <form data-testid="login-form" onSubmit={handleLogin}>
          <label>Email <input data-testid="login-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
          <label>Password <input data-testid="login-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
          <button data-testid="login-submit" type="submit">Sign in</button>
        </form>
        {error && <p data-testid="login-error" role="alert">{error}</p>}
      </main>
    );
  }

  const has = (key) => permissions[key]?.effect === 'allow';
  const shellColor = org?.theme === 'amber' ? '#fff0d5' : '#e9f0ff';
  const navItems = [
    ['devices', has('device:list')],
    ['people', has('user:read') || has('user:invite')],
    ['grants', has('user:read') || has('grant:create') || has('grant:revoke')],
    ['sessions', has('session:view') || has('session:start')],
    ['audit', has('audit:read')],
    ['admin', has('org:update') || has('org:delete')],
  ];

  return (
    <main data-testid="app-shell" data-org-id={org?.id} data-org-theme={org?.theme}
      style={{ minHeight: '100vh', backgroundColor: shellColor, color: '#182235', fontFamily: 'system-ui', padding: 24 }}>
      <header>
        <h1>RemoteOps</h1>
        <p>Signed in as {user?.name} · Active organization: <strong>{org?.name}</strong></p>
        <p>Role: <span data-testid="active-role">{orgs.find((item) => item.id === org?.id)?.role ?? permissions.role}</span></p>
        <div aria-label="Organizations">
          {orgs.map((item) => (
            <button key={item.id} data-testid="org-option" data-org-id={item.id}
              aria-current={item.id === org?.id ? 'true' : undefined}
              onClick={() => switchOrganization(item.id)}>{item.name}</button>
          ))}
          {has('org:update') && <button data-testid="create-org" onClick={createOrganization}>Create organization</button>}
        </div>
      </header>

      {error && <p role="alert">{error}</p>}
      <nav aria-label="Main navigation">
        {navItems.map(([name, allowed]) => allowed && (
          <button key={name} data-testid={`nav-${name}`} onClick={() => openSection(name)}>{name}</button>
        ))}
      </nav>

      {section === 'devices' && (
        <section><h2>Devices</h2>
          {devices.length === 0 && <p data-testid="devices-empty">No devices in this organization.</p>}
          <table><tbody>{devices.map((device) => (
            <tr key={device.id} data-testid="device-row" data-device-id={device.id}>
              <td>{device.name}</td><td>{device.kind}</td><td>{device.online ? 'Online' : 'Offline'}</td>
              {['device:control', 'device:terminal', 'device:file_transfer'].map((key) => device.permissions[key]?.effect === 'allow' && (
                <td key={key}><button data-permission={key} data-state="unlocked">{key.split(':')[1]}</button></td>
              ))}
            </tr>
          ))}</tbody></table>
        </section>
      )}

      {section === 'people' && <section><h2>People</h2><table><tbody>{users.map((person) => (
        <tr key={person.id} data-testid="user-row" data-user-id={person.id}><td>{person.name}</td><td>{person.email}</td><td>{person.role}</td></tr>
      ))}</tbody></table></section>}

      {section === 'grants' && <section><h2>Grants</h2>
        {has('grant:create') && <button data-testid="new-grant" onClick={() => setGrantForm({ ...grantForm, userId: users[0]?.id ?? '' })}>New grant</button>}
        {has('grant:create') && grantForm.userId && <form onSubmit={createGrant}>
          <label>User <select data-testid="grant-user" value={grantForm.userId} onChange={(event) => setGrantForm({ ...grantForm, userId: event.target.value })}>
            {users.filter((person) => person.id !== user?.id).map((person) => <option key={person.id} value={person.id}>{person.name}</option>)}
          </select></label>
          <label>Device <select data-testid="grant-device" value={grantForm.deviceId} onChange={(event) => setGrantForm({ ...grantForm, deviceId: event.target.value })}>
            <option value="">All devices</option>{devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
          </select></label>
          <label>Effect <select data-testid="grant-effect" value={grantForm.effect} onChange={(event) => setGrantForm({ ...grantForm, effect: event.target.value })}>
            <option value="allow">Allow</option><option value="deny">Deny</option>
          </select></label>
          {Object.keys(permissions).map((key) => <label key={key}><input type="checkbox" data-permission-key={key}
            checked={grantForm.permissions.includes(key)} onChange={(event) => setGrantForm({ ...grantForm, permissions: event.target.checked ? [...grantForm.permissions, key] : grantForm.permissions.filter((item) => item !== key) })} />{key}</label>)}
          <button data-testid="grant-submit" type="submit">Save grant</button>
        </form>}
        {grants.map((grant) => <article key={grant.id} data-testid="grant-row" data-effect={grant.effect}>
          {grant.effect} {grant.permissions.join(', ')} for {grant.user_name}{grant.device_name ? ` on ${grant.device_name}` : ' on all devices'}
          {has('grant:revoke') && <button data-testid="revoke-grant">Revoke</button>}
        </article>)}
      </section>}

      {section === 'sessions' && <section><h2>Sessions</h2>{sessions.map((session) => <article key={session.id}>{session.mode} · {session.state}</article>)}</section>}
      {section === 'audit' && <section><h2>Audit</h2>{events.map((event) => <article key={event.id}>{event.action} · {event.result}</article>)}</section>}
      {section === 'admin' && <section><h2>Organization settings</h2>
        {has('org:update') && <button data-testid="rename-org">Rename organization</button>}
        {has('org:delete') && <button data-testid="delete-org">Delete organization</button>}
      </section>}
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
