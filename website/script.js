const header = document.querySelector('.site-header');
const navToggle = document.querySelector('.nav-toggle');
const navLinks = document.querySelector('#nav-links');
const demoOutput = document.querySelector('#demo-output');

const demoSteps = [
  {
    title: 'Authorized task action',
    lines: [
      '$ kechaa run --task contract.yaml -- python agent.py summarize ./workspace/report.txt',
      'contract: workspace root + approved executable + active lease',
      'grant: signature verified, action bound, single-use token issued',
      'decision: ALLOW',
      'audit: contract_confirmed → grant_prepared → grant_consumed'
    ]
  },
  {
    title: 'Risky tool request',
    lines: [
      '$ agent requests: tool effect { read: ./workspace, network: external }',
      'tool gateway: effect contract evaluated before action',
      'history: prior file access is part of the policy context',
      'decision: DENY',
      'posture: trusted event recorded and grants tightened'
    ]
  },
  {
    title: 'Follow-up decision',
    lines: [
      '$ agent retries through another path',
      'history: previous denial changes the decision context',
      'lease: checked against current session state',
      'decision: ADMIN REVIEW',
      'audit: sequence preserved for recovery and investigation'
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
  document.querySelectorAll('.reveal, .section-heading, .feature-card, .risk-grid article, .use-grid article, .demo-panel, .docs-list a').forEach((element) => observer.observe(element));
} else {
  document.querySelectorAll('.reveal').forEach((element) => element.classList.add('is-visible'));
}

window.addEventListener('scroll', setHeaderState, { passive: true });
setHeaderState();
setDemoStep(0);
