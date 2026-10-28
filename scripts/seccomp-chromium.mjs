// Derive deploy/seccomp-chromium.json from the containers-common default seccomp
// profile (Apache-2.0, containers/common; see NOTICE), so the
// container can run Chromium WITH its sandbox instead of CHROMIUM_NO_SANDBOX=true.
//
// The only change: allow chroot without CAP_SYS_CHROOT. Chromium's namespace
// sandbox creates an unprivileged user namespace and chroots inside it, where it
// does hold that capability. The stock profile decides by the container's own
// (dropped) capabilities and answers EPERM, so the zygote dies at startup. The
// kernel still refuses chroot to any process without the capability in its own
// namespace. clone/unshare/setns are already allowed by containers-common.
//
// Regenerate after containers-common updates (then re-copy it for Quadlet):
//   node scripts/seccomp-chromium.mjs [/usr/share/containers/seccomp.json] [deploy/seccomp-chromium.json]
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const source = process.argv[2] ?? '/usr/share/containers/seccomp.json';
const target = process.argv[3] ?? fileURLToPath(new URL('../deploy/seccomp-chromium.json', import.meta.url));
const profile = JSON.parse(readFileSync(source, 'utf8'));

const empty = (value) => value === undefined || Object.keys(value).length === 0;
// Accept only the exact stock shape: a single-name rule gated on CAP_SYS_CHROOT
// alone, with no argument filters or other conditions that dropping it could lose.
const capGate = (rule, kind, other) =>
  (rule.args ?? []).length === 0 && empty(rule[other]) &&
  Object.keys(rule[kind] ?? {}).join() === 'caps' &&
  rule[kind].caps.length === 1 && rule[kind].caps[0] === 'CAP_SYS_CHROOT';

let allowed = 0;
profile.syscalls = profile.syscalls.flatMap((rule) => {
  if (!(rule.names ?? [rule.name]).includes('chroot')) return [rule];
  const ok = rule.names?.length === 1 && (rule.action === 'SCMP_ACT_ALLOW'
    ? capGate(rule, 'includes', 'excludes')
    : rule.action === 'SCMP_ACT_ERRNO' && capGate(rule, 'excludes', 'includes'));
  if (!ok) throw new Error(`unexpected chroot rule in ${source}: ${JSON.stringify(rule)}`);
  if (rule.action !== 'SCMP_ACT_ALLOW') return []; // drop the EPERM fallback
  allowed++;
  const { includes: _includes, ...unconditional } = rule;
  return [unconditional];
});
if (allowed !== 1) throw new Error(`expected exactly one capability-gated chroot rule in ${source}`);

// Write atomically so a failed run never leaves a truncated profile behind.
writeFileSync(`${target}.tmp`, JSON.stringify(profile, null, 2) + '\n');
renameSync(`${target}.tmp`, target);
console.log(`wrote ${target} from ${source}`);
