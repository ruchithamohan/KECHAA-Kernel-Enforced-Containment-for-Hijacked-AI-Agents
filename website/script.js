const header = document.querySelector('.topbar');
const navToggle = document.querySelector('.nav-toggle');
const navLinks = document.querySelector('#nav-links');
const demoOutput = document.querySelector('#demo-output');
const mapGroup = document.querySelector('#map-transform');
const mapSvg = document.querySelector('#architecture-map');
const nodeTitle = document.querySelector('#node-title');
const nodeBody = document.querySelector('#node-body');
const nodeMeta = document.querySelector('#node-meta');

const demoSteps = [
  ['grant', ['$ run_open: contract confirmed for session', '$ prepare: argv + cwd + policy + effects are digested', '$ grant: Ed25519 signature issued', '$ consume: single-use grant adopted or simulated', 'audit: contract_confirmed → grant_prepared → grant_consumed']],
  ['tool', ['$ tool_request: FileRead / MCP-style request declares effects', '$ policy: read/write roots and network mode evaluated', '$ history: prior posture and denials are included', '$ decision: allow / ask / deny', 'audit: tool_request event stored']],
  ['posture', ['$ trusted_event: supervisor/tool/kernel/admin signal arrives', '$ engine: posture moves normal → guarded → lockdown', '$ grants: issued and outstanding envelopes revoked', '$ recovery: administrator-reviewed transition', 'audit: posture_changed + signed checkpoint']]
];

const nodes = {
  agent: ['Agent / CLI', 'Entry surface for humans, agents and adapters. The CLI translates command, policy, audit, hook and MCP-check operations into local API requests.', [['Module', 'kechaa/cli.py'], ['Protocol', 'Unix socket JSON messages']]],
  tool: ['Tool Request', 'Tool and MCP-style requests are modeled as declared effects. The engine evaluates read/write/network effects before an integration proceeds.', [['Operation', 'tool_request'], ['Contract kind', 'mcp_effect_contract / file_effect_contract']]],
  admin: ['Admin Ops', 'Administrative paths import policy, approve guarded grants, renew leases, quarantine/recover runs and create audit checkpoints.', [['Operations', 'policy_import, grant_approve, checkpoint'], ['Role', 'administrative local API caller']]],
  daemon: ['Daemon Server', 'Bounded local server that authenticates peer credentials, dispatches operations, supervises active workers and coordinates cleanup.', [['Module', 'kechaa/daemon.py'], ['Dispatch', 'run_open, prepare, execute, tool_request, audit_*']]],
  engine: ['Authority Engine', 'The authorization core. It owns run state, signed grants, leases, trusted signals, history-aware decisions, quarantine and recovery.', [['Module', 'kechaa/engine.py'], ['Key flow', 'open_run → prepare → consume → finish']]],
  policy: ['Policy + Effects', 'Policy validation, rule evaluation, path scoping, executable/input identity and effect-envelope construction.', [['Modules', 'policy.py, effects.py'], ['Inputs', 'argv, cwd, roots, executable digests']]],
  store: ['SQLite State', 'Persistent state for policies, runs and grants with transactional updates around security decisions.', [['Module', 'kechaa/store.py'], ['Tables', 'meta, policies, runs, grants']]],
  history: ['History', 'Ordered run history used by the engine when evaluating repeated denials, tool requests, lease state and posture.', [['Table', 'history'], ['Use', 'history-aware authorization']]],
  audit: ['Audit Chain', 'Signed, hash-chained records plus checkpoints and anchors for external verification and investigation.', [['Tables', 'audit, anchors'], ['Operations', 'audit_verify, audit_checkpoint, audit_anchor']]],
  supervisor: ['Supervisor', 'Execution path that creates cgroups, starts the worker, monitors output/time/CPU budgets and terminates active process trees.', [['Module', 'daemon.execute'], ['Boundary handoff', 'cgroup_create → worker.py']]],
  worker: ['Worker', 'Child process that installs controls, drops authority and execs the approved action after receiving a grant configuration.', [['Module', 'kechaa/worker.py'], ['Action', 'execve approved argv']]],
  kernel: ['Linux Primitives', 'OS mechanisms used by the worker/backend: cgroup v2, namespaces, Landlock, seccomp, no_new_privs and credential drop.', [['Module', 'backends/linux.py'], ['Mechanisms', 'cgroup, namespaces, Landlock, seccomp']]]
};

let transform = { x: 0, y: 0, k: 1 };
let drag = null;

function setHeaderState() { if (header) header.dataset.elevated = String(window.scrollY > 10); }
function applyTransform() { if (mapGroup) mapGroup.setAttribute('transform', `translate(${transform.x} ${transform.y}) scale(${transform.k})`); }
function setNode(key) {
  const item = nodes[key];
  if (!item) return;
  document.querySelectorAll('.arch-node').forEach(node => node.classList.toggle('is-active', node.dataset.node === key));
  nodeTitle.textContent = item[0];
  nodeBody.textContent = item[1];
  nodeMeta.innerHTML = item[2].map(([term, desc]) => `<div><dt>${term}</dt><dd>${desc}</dd></div>`).join('');
}
function setDemo(index) {
  const [title, lines] = demoSteps[index] || demoSteps[0];
  demoOutput.textContent = [`# ${title}`, ...lines].join('\n');
  document.querySelectorAll('[data-demo-step]').forEach((button, i) => {
    const active = i === index;
    button.setAttribute('aria-pressed', String(active));
    button.setAttribute('aria-selected', String(active));
    button.setAttribute('tabindex', active ? '0' : '-1');
  });
}

navToggle?.addEventListener('click', () => {
  const open = navLinks.classList.toggle('is-open');
  navToggle.setAttribute('aria-expanded', String(open));
});
navLinks?.addEventListener('click', event => {
  if (event.target instanceof HTMLAnchorElement) {
    navLinks.classList.remove('is-open');
    navToggle?.setAttribute('aria-expanded', 'false');
  }
});
document.querySelectorAll('[data-demo-step]').forEach((button, index) => button.addEventListener('click', () => setDemo(index)));
document.querySelectorAll('.arch-node').forEach(node => {
  node.addEventListener('mouseenter', () => setNode(node.dataset.node));
  node.addEventListener('focus', () => setNode(node.dataset.node));
  node.addEventListener('click', () => setNode(node.dataset.node));
});
document.querySelectorAll('[data-zoom]').forEach(button => button.addEventListener('click', () => {
  const action = button.dataset.zoom;
  if (action === 'reset') transform = { x: 0, y: 0, k: 1 };
  if (action === 'in') transform.k = Math.min(1.8, transform.k + .16);
  if (action === 'out') transform.k = Math.max(.72, transform.k - .16);
  applyTransform();
}));
mapSvg?.addEventListener('pointerdown', event => { drag = { px: event.clientX, py: event.clientY, x: transform.x, y: transform.y }; mapSvg.setPointerCapture(event.pointerId); });
mapSvg?.addEventListener('pointermove', event => {
  if (!drag) return;
  transform.x = drag.x + (event.clientX - drag.px) / transform.k;
  transform.y = drag.y + (event.clientY - drag.py) / transform.k;
  applyTransform();
});
mapSvg?.addEventListener('pointerup', () => { drag = null; });
mapSvg?.addEventListener('pointercancel', () => { drag = null; });
mapSvg?.addEventListener('lostpointercapture', () => { drag = null; });

if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver(entries => entries.forEach(entry => {
    if (entry.isIntersecting) { entry.target.classList.add('is-visible'); observer.unobserve(entry.target); }
  }), { threshold: .12 });
  document.querySelectorAll('.reveal, .section-head, .principles article, .capability-marquee article, .use-list article, .architecture-shell, .developer-panel').forEach(el => observer.observe(el));
} else document.querySelectorAll('.reveal').forEach(el => el.classList.add('is-visible'));

window.addEventListener('scroll', setHeaderState, { passive: true });
setHeaderState();
setDemo(0);
setNode('engine');
applyTransform();
