const header = document.querySelector('.site-header');
const navToggle = document.querySelector('.nav-toggle');
const navLinks = document.querySelector('#nav-links');
const demoOutput = document.querySelector('#demo-output');

const demoSteps = [
  {
    title: 'Permitted task action',
    lines: [
      '$ kechaa run --task contract.yaml -- python agent.py summarize ./fixtures/report.txt',
      'grant: verified signature, unused grant id, active lease',
      'history: no prior violations for agent=session-dev-01',
      'decision: ALLOW — action matches task contract',
      'audit: event anchored with decision, grant id and session id'
    ]
  },
  {
    title: 'Prohibited external effect',
    lines: [
      '$ agent requests: upload ./fixtures/secret.txt to external endpoint',
      'effect contract: network egress not authorized for this task',
      'history: sensitive file access occurred earlier in session',
      'decision: DENY + posture escalated',
      'enforcement: supported gateways fail closed; Linux OS enforcement requires LC certification'
    ]
  },
  {
    title: 'Follow-up after suspicious sequence',
    lines: [
      '$ agent retries with a different tool path',
      'history: previous denial influences the next decision',
      'lease: still active, but risk posture is quarantined',
      'decision: DENY — sequence violates policy context',
      'recovery: administrator can inspect audit trail and restore or terminate session'
    ]
  }
];

function setHeaderState() {
  if (header) header.dataset.elevated = String(window.scrollY > 12);
}

function setDemoStep(index) {
  if (!demoOutput) return;
  const step = demoSteps[index] || demoSteps[0];
  demoOutput.textContent = [`# ${step.title}`, ...step.lines].join('\n');
  document.querySelectorAll('[data-demo-step]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.demoStep === String(index)));
  });
}

navToggle?.addEventListener('click', () => {
  const isOpen = navLinks?.classList.toggle('is-open');
  navToggle.setAttribute('aria-expanded', String(Boolean(isOpen)));
});

navLinks?.addEventListener('click', (event) => {
  if (event.target instanceof HTMLAnchorElement) {
    navLinks.classList.remove('is-open');
    navToggle?.setAttribute('aria-expanded', 'false');
  }
});

document.querySelectorAll('[data-demo-step]').forEach((button) => {
  button.addEventListener('click', () => setDemoStep(Number(button.dataset.demoStep)));
});

if ('IntersectionObserver' in window) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.14 });
  document.querySelectorAll('.reveal, .section-heading, .feature-card, .risk-grid article, .use-grid article, .demo-panel, .docs-list a, details').forEach((element) => observer.observe(element));
} else {
  document.querySelectorAll('.reveal').forEach((element) => element.classList.add('is-visible'));
}

window.addEventListener('scroll', setHeaderState, { passive: true });
setHeaderState();
setDemoStep(0);
