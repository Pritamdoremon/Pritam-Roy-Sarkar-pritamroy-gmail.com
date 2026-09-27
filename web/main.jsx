import React from 'react';
import { createRoot } from 'react-dom/client';

// The starter shell. Replace this with the console.
//
// The console contract (UI-INVENTORY.md) is what the shipped UI tests read, and it is
// fixed: elements are present or ABSENT, never disabled, and every permission-gated
// element is resolved by the SERVER. There is no role-to-permission table under web/.
//
// The attributes the tests read:
//   <div    data-testid="app-shell"  data-org-id="org_acme" data-org-theme="cobalt">
//   <button data-testid="org-option" data-org-id="org_globex">
//   <tr     data-testid="device-row" data-device-id="dev_lab_mac_01">
//   <tr     data-testid="user-row"   data-user-id="usr_sam">
//   <button data-permission="device:control" data-state="unlocked">
//
// Everything else — layout, visual language, per-org identity — is yours.

function Placeholder() {
  return (
    <main style={{ fontFamily: 'ui-sans-serif, system-ui, sans-serif', padding: 32, lineHeight: 1.5 }}>
      <h1 style={{ margin: '0 0 4px' }}>RemoteOps</h1>
      <p style={{ color: '#5b6270', margin: 0 }}>
        Starter shell. The API and the console are yours to write — see <code>README.md</code>.
      </p>
      <p style={{ color: '#5b6270', margin: '16px 0 0', fontSize: 14 }}>
        First: <code>server/auth.js</code>, then <code>server/context.js</code> and{' '}
        <code>server/permissions.js</code>.
      </p>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<Placeholder />);
