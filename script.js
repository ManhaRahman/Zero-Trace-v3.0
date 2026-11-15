const outputEl = document.getElementById('output');
const formEl = document.getElementById('command-form');
const inputEl = document.getElementById('command-input');
const timerEl = document.getElementById('timer');
const hostLabelEl = document.getElementById('host-label');
const pivotCountEl = document.getElementById('pivot-count');
const promptLabelEl = document.getElementById('prompt-label');
const terminalEl = document.getElementById('terminal');

let timeLeft = 500.0;
let gameOver = false;
let timerInterval = null;
let currentHost = 'workstation';
const discoveredHosts = new Set(['workstation']);
const scannedHosts = new Set();
const commandHistory = [];
let historyIndex = -1;

function stringToHex(str) {
  let hex = '';
  for (let i = 0; i < str.length; i++) {
    hex += str.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return hex.toUpperCase();
}

function hexToString(hex) {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    throw new Error('Invalid hex');
  }
  let str = '';
  for (let i = 0; i < clean.length; i += 2) {
    str += String.fromCharCode(parseInt(clean.substr(i, 2), 16));
  }
  return str;
}

const seeds = [
  {
    relayIp: '10.10.2.15',
    relayUser: 'ops_admin',
    relayPass: 'N3tW0rk_R3l4y',
    dbIp: '10.10.5.40',
    dbUser: 'db_auditor',
    dbPass: 'Qu3ry_M4st3r',
    vaultIp: '10.10.9.99',
    vaultUser: 'sec_root',
    vaultPass: 'K3rn3l_P4n1c',
    roguePid: '4812',
    attackerIp: '185.220.101.44',
    killCode: 'OMEGA-774'
  },
  {
    relayIp: '10.10.4.88',
    relayUser: 'dev_lead',
    relayPass: 'Sh4d0w_S0ck3t',
    dbIp: '10.10.7.22',
    dbUser: 'sql_ops',
    dbPass: 'D4t4_Sh4rd9',
    vaultIp: '10.10.12.50',
    vaultUser: 'vault_ops',
    vaultPass: 'B1n4ry_Gh0st',
    roguePid: '7391',
    attackerIp: '91.132.147.19',
    killCode: 'AEGIS-902'
  }
];

const s = seeds.at(Math.floor(Math.random() * seeds.length));

function buildSyslog() {
  const noise = [
    'systemd: Started Session 412 of user cron.',
    'CRON: (root) CMD (/usr/local/bin/healthcheck.sh)',
    'sshd: Accepted publickey for monitor from 10.10.0.5 port 51234',
    'kernel: [41209.112] eth0: link up, 1000Mbps, full-duplex',
    'nginx: 10.10.0.12 - GET /api/v1/status HTTP/1.1 200',
    'auditd: USER_ACCT pid=2309 uid=0 msg=op=PAM:accounting'
  ];
  const lines = [];
  for (let i = 0; i < 40; i++) {
    const min = String(i % 60).padStart(2, '0');
    const msg = noise.at(i % noise.length);
    lines.push('Nov 14 03:' + min + ':11 relay-node ' + msg);
  }
  lines.splice(14, 0, 'Nov 14 03:14:22 relay-node sshd: Accepted password for ' + s.dbUser + ' from ' + s.dbIp + ' (b64_key=' + btoa(s.dbPass) + ')');
  lines.splice(29, 0, 'Nov 14 03:29:51 relay-node kernel: [UFW ALERT] OUTBOUND C2 DETECTED -> DST=' + s.attackerIp + ' PROTO=TCP DPT=6667');
  return lines;
}

const servers = {
  workstation: {
    name: 'workstation',
    user: 'analyst',
    hint: 'Read briefing.txt and mail_archive.txt. Decode key_backup.b64, nmap the relay IP, and ssh into it.',
    files: {
      'briefing.txt': [
        'INCIDENT #901-X // ENTERPRISE BREACH CONTAINMENT',
        'A sophisticated threat actor has infiltrated our multi-tier infrastructure:',
        '  TIER 1: Staging Relay  -> Investigate network & auth logs',
        '  TIER 2: Database Node  -> Recover hex-encoded Vault root credentials',
        '  TIER 3: Core Vault     -> Block C2 traffic, kill wiper daemon, and trigger override',
        'Use "map" at any time to visualize discovered network nodes.'
      ],
      'mail_archive.txt': [
        'From: netops@corp.internal',
        'To: ' + s.relayUser + '@corp.internal',
        'Subject: Staging Relay Access',
        '----------------------------------------',
        'The staging relay host is online at ' + s.relayIp + '.',
        'Before connecting via SSH, run "nmap ' + s.relayIp + '" to verify its SSH port is active.',
        'Your Base64-encoded login token is stored in key_backup.b64.'
      ],
      'key_backup.b64': [
        btoa(s.relayPass)
      ]
    },
    processes: [
      { pid: '101', user: 'root', cmd: '/sbin/init' },
      { pid: '402', user: 'analyst', cmd: '/bin/bash' }
    ],
    nmap: [
      'PORT     STATE  SERVICE',
      '22/tcp   open   OpenSSH 8.9p1'
    ]
  },

  [s.relayIp]: {
    name: s.relayIp,
    user: s.relayUser,
    hint: 'Use "grep Accepted syslog" to find the Database Cluster login, and "grep ALERT syslog" to spot the attacker IP.',
    files: {
      'syslog': buildSyslog(),
      'topology_notes.txt': [
        'INTERNAL ROUTING TABLE:',
        '  - Staging Relay (' + s.relayIp + ') bridges traffic to Database Cluster (' + s.dbIp + ').',
        '  - Core Vault (' + s.vaultIp + ') is isolated and only accepts SSH from the Database Cluster.',
        '  - Filter syslog with grep (e.g. grep Accepted syslog / grep ALERT syslog).'
      ]
    },
    processes: [
      { pid: '101', user: 'root', cmd: '/sbin/init' },
      { pid: '912', user: s.relayUser, cmd: '/bin/bash' },
      { pid: '1405', user: 'root', cmd: '/usr/sbin/rsyslogd' }
    ],
    nmap: [
      'PORT     STATE  SERVICE',
      '22/tcp   open   OpenSSH 8.9p1',
      '514/tcp  open   syslog-ng'
    ]
  },

  [s.dbIp]: {
    name: s.dbIp,
    user: s.dbUser,
    hint: 'Inspect db_dump.sql and vault_cred.hex. Use "hex2ascii [hex]" to decode the Vault password, nmap the Vault IP, and ssh in.',
    files: {
      'db_dump.sql': [
        '-- EMERGENCY MEMORY SNAPSHOT',
        'INSERT INTO audit_trail VALUES (1, "vault_target", "' + s.vaultIp + '");',
        'INSERT INTO audit_trail VALUES (2, "vault_admin_user", "' + s.vaultUser + '");',
        'INSERT INTO audit_trail VALUES (3, "auth_encoding", "HEXADECIMAL -> see vault_cred.hex");'
      ],
      'vault_cred.hex': [
        stringToHex(s.vaultPass)
      ]
    },
    processes: [
      { pid: '101', user: 'root', cmd: '/sbin/init' },
      { pid: '2210', user: s.dbUser, cmd: '/bin/bash' },
      { pid: '3306', user: 'postgres', cmd: '/usr/lib/postgresql/15/bin/postgres' }
    ],
    nmap: [
      'PORT     STATE  SERVICE',
      '22/tcp   open   OpenSSH 8.9p1',
      '5432/tcp open   postgresql'
    ]
  },

  [s.vaultIp]: {
    name: s.vaultIp,
    user: s.vaultUser,
    malwareAlive: true,
    firewallBlocked: false,
    hint: 'On the Vault: 1) Block attacker IP with "ufw block [ip]", 2) Kill rogue PID from "ps", 3) Decode kill_code.enc, 4) Run "override [attacker_ip] [kill_code]".',
    files: {
      'vault_protocol.txt': [
        '=== CORE VAULT CONTAINMENT CHECKLIST ===',
        'Before executing "override [ATTACKER_IP] [KILL_CODE]", two conditions MUST be met:',
        '  1. Active C2 exfiltration channel must be severed via: ufw block [ATTACKER_IP]',
        '  2. Any unauthorized wiper process locking memory must be terminated via: kill [PID]'
      ],
      'kill_code.enc': [
        btoa(s.killCode)
      ]
    },
    processes: [
      { pid: '101', user: 'root', cmd: '/sbin/init' },
      { pid: '1102', user: s.vaultUser, cmd: '/bin/bash' },
      { pid: s.roguePid, user: 'unknown', cmd: './wiper_daemon --lock-memory --exfil' },
      { pid: '5010', user: 'root', cmd: '/usr/sbin/auditd' }
    ],
    nmap: [
      'PORT     STATE  SERVICE',
      '22/tcp   open   OpenSSH 8.9p1',
      '9001/tcp open   vault-core-daemon'
    ]
  }
};

function printLine(text, className = 'line-white') {
  const div = document.createElement('div');
  div.className = className;
  div.textContent = text;
  outputEl.appendChild(div);
  outputEl.scrollTop = outputEl.scrollHeight;
}

function triggerPenalty(seconds, message) {
  timeLeft = Math.max(0, timeLeft - seconds);
  printLine('[!] ' + message + ' (-' + seconds + 's)', 'line-error');
  terminalEl.classList.add('error-flash');
  setTimeout(() => terminalEl.classList.remove('error-flash'), 300);
}

function startTimer() {
  timerInterval = setInterval(() => {
    if (gameOver) return;
    timeLeft -= 0.1;
    if (timeLeft <= 0) {
      timeLeft = 0;
      endGame(false);
    }
    timerEl.textContent = timeLeft.toFixed(1) + 's';
  }, 100);
}

function endGame(didWin) {
  gameOver = true;
  clearInterval(timerInterval);
  inputEl.disabled = true;
  printLine('==========================================================', 'line-purple');
  if (didWin) {
    printLine('CONTAINMENT COMPLETE. C2 SEVERED. WIPER PURGED. VAULT SECURED.', 'line-success');
    printLine('MISSION ACCOMPLISHED WITH ' + timeLeft.toFixed(1) + 's REMAINING.', 'line-purple');
  } else {
    printLine('LOCKOUT TRIGGERED. CORE VAULT WIPED.', 'line-error');
  }
}

function switchHost(hostKey) {
  currentHost = hostKey;
  discoveredHosts.add(hostKey);
  pivotCountEl.textContent = discoveredHosts.size + '/4';
  const srv = servers[hostKey];
  hostLabelEl.textContent = srv.name;
  promptLabelEl.textContent = srv.user + '@' + srv.name + ':~$';
}

function renderMap() {
  const rStatus = discoveredHosts.has(s.relayIp) ? '[COMPROMISED]' : '[LOCKED]';
  const dStatus = discoveredHosts.has(s.dbIp) ? '[COMPROMISED]' : '[LOCKED]';
  const vStatus = discoveredHosts.has(s.vaultIp) ? '[COMPROMISED]' : '[LOCKED]';

  printLine('=== ENTERPRISE NETWORK TOPOLOGY ===', 'line-purple');
  printLine('  [workstation] (YOU)', 'line-white');
  printLine('       |', 'line-muted');
  printLine('       v', 'line-muted');
  printLine('  [' + s.relayIp + ']  Staging Relay    ' + rStatus, discoveredHosts.has(s.relayIp) ? 'line-purple' : 'line-muted');
  printLine('       |', 'line-muted');
  printLine('       v', 'line-muted');
  printLine('  [' + s.dbIp + ']  Database Cluster ' + dStatus, discoveredHosts.has(s.dbIp) ? 'line-purple' : 'line-muted');
  printLine('       |', 'line-muted');
  printLine('       v', 'line-muted');
  printLine('  [' + s.vaultIp + ']  Core Vault       ' + vStatus, discoveredHosts.has(s.vaultIp) ? 'line-purple' : 'line-muted');
}

function handleCommand(rawInput) {
  const parts = rawInput.trim().split(/\s+/);
const cmd = (parts.at(0) || '').toLowerCase();
const arg1 = parts.at(1);
const arg2 = parts.at(2);
const srv = servers[currentHost];
switch (cmd) {
case 'help':
printLine('SOC INCIDENT RESPONSE TOOLKIT:', 'line-purple');
printLine('  map                         Display network topology & pivot progress', 'line-white');
printLine('  ls                          List files in current directory', 'line-white');
printLine('  cat [file]                  Read file contents', 'line-white');
printLine('  grep [keyword] [file]       Filter lines matching keyword in a file', 'line-white');
printLine('  nmap [ip]                   Scan target host for open ports', 'line-white');
printLine('  ps                          List active running processes', 'line-white');
printLine('  kill [pid]                  Terminate a process by PID', 'line-white');
printLine('  ufw block [ip]              Add firewall rule to block an external IP', 'line-white');
printLine('  ssh [user]@[ip] [password]  Connect to a scanned remote host', 'line-white');
printLine('  decode [base64]             Decode a Base64 string', 'line-white');
printLine('  hex2ascii [hex]             Convert hexadecimal string to plain text', 'line-white');
printLine('  hint                        Request tactical hint (-15s time penalty)', 'line-white');
printLine('  override [ip] [code]        Execute final Vault containment', 'line-white');
printLine('  clear                       Clear terminal output', 'line-white');
break;
case 'map':
renderMap();
break;
case 'ls':
Object.keys(srv.files).forEach(f => printLine('  ' + f, 'line-white'));
break;
case 'cat':
if (!arg1) {
printLine('Usage: cat [file]', 'line-error');
break;
}
const content = srv.files[arg1];
if (!content) {
printLine('cat: ' + arg1 + ': No such file', 'line-error');
break;
}
content.forEach(line => printLine(line, 'line-white'));
break;
case 'grep':
if (!arg1 || !arg2) {
printLine('Usage: grep [keyword] [file]', 'line-error');
break;
}
const targetFile = srv.files[arg2];
if (!targetFile) {
printLine('grep: ' + arg2 + ': No such file', 'line-error');
break;
}
const matches = targetFile.filter(line => line.toLowerCase().includes(arg1.toLowerCase()));
if (matches.length === 0) {
printLine('(no matches for "' + arg1 + '" in ' + arg2 + ')', 'line-muted');
} else {
matches.forEach(m => printLine(m, 'line-purple'));
}
break;
case 'nmap':
if (!arg1) {
printLine('Usage: nmap [target_ip]', 'line-error');
break;
}
if (!servers[arg1]) {
triggerPenalty(5, 'Host ' + arg1 + ' unreachable or down.');
break;
}
scannedHosts.add(arg1);
printLine('Starting Nmap scan on ' + arg1 + '...', 'line-purple');
servers[arg1].nmap.forEach(line => printLine('  ' + line, 'line-white'));
break;
case 'ps':
printLine('  PID    USER       COMMAND', 'line-muted');
srv.processes.forEach(p => {
printLine('  ' + p.pid.padEnd(6) + ' ' + p.user.padEnd(10) + ' ' + p.cmd, 'line-white');
});
break;
case 'kill':
if (!arg1) {
printLine('Usage: kill [pid]', 'line-error');
break;
}
const idx = srv.processes.findIndex(p => p.pid === arg1);
if (idx === -1) {
printLine('kill: (' + arg1 + ') - No such process', 'line-error');
} else {
const targetProc = srv.processes.at(idx);
if (arg1 === '101' || targetProc.cmd.includes('bash') || targetProc.cmd.includes('sshd')) {
triggerPenalty(10, 'CRITICAL SYSTEM PROCESS (' + arg1 + ') TERMINATION BLOCKED');
} else {
srv.processes.splice(idx, 1);
if (currentHost === s.vaultIp && arg1 === s.roguePid) {
srv.malwareAlive = false;
}
printLine('Process ' + arg1 + ' (' + targetProc.cmd + ') terminated.', 'line-success');
}
}
break;
case 'ufw':
if (arg1 !== 'block' || !arg2) {
printLine('Usage: ufw block [ip_address]', 'line-error');
break;
}
if (currentHost !== s.vaultIp) {
triggerPenalty(5, 'Firewall rules can only be modified on the Core Vault.');
break;
}
if (arg2 === s.attackerIp) {
servers[s.vaultIp].firewallBlocked = true;
printLine('UFW RULE ADDED: DENY OUTBOUND TO ' + arg2, 'line-success');
} else {
triggerPenalty(8, 'Invalid target IP ' + arg2 + ' — verify attacker C2 IP in relay logs.');
}
break;
case 'ssh':
if (!arg1 || !arg2) {
printLine('Usage: ssh [user]@[ip] [password]', 'line-error');
break;
}
const creds = arg1.split('@');
const user = creds.at(0);
const ip = creds.at(1);
if (!scannedHosts.has(ip) && servers[ip]) {
triggerPenalty(5, 'Unknown host fingerprint for ' + ip + '. Run "nmap ' + ip + '" first.');
break;
}
if (ip === s.relayIp && user === s.relayUser && arg2 === s.relayPass) {
switchHost(s.relayIp);
printLine('Authenticated to Staging Relay (' + s.relayIp + ').', 'line-success');
} else if (ip === s.dbIp && user === s.dbUser && arg2 === s.dbPass) {
switchHost(s.dbIp);
printLine('Authenticated to Database Cluster (' + s.dbIp + ').', 'line-success');
} else if (ip === s.vaultIp && user === s.vaultUser && arg2 === s.vaultPass) {
if (currentHost !== s.dbIp) {
triggerPenalty(8, 'Connection timed out: Vault only accepts SSH from Database Cluster.');
break;
}
switchHost(s.vaultIp);
printLine('Authenticated to Core Vault (' + s.vaultIp + ').', 'line-success');
} else {
triggerPenalty(10, 'SSH Permission denied (invalid user, host, or password).');
}
break;
case 'decode':
if (!arg1) {
printLine('Usage: decode [base64_string]', 'line-error');
break;
}
try {
printLine(atob(arg1), 'line-purple');
} catch (e) {
triggerPenalty(5, 'Invalid Base64 input.');
}
break;
case 'hex2ascii':
if (!arg1) {
printLine('Usage: hex2ascii [hex_string]', 'line-error');
break;
}
try {
printLine(hexToString(arg1), 'line-purple');
} catch (e) {
triggerPenalty(5, 'Invalid Hexadecimal string.');
}
break;
case 'hint':
timeLeft = Math.max(0, timeLeft - 15);
printLine('[HINT -15s]: ' + srv.hint, 'line-purple');
break;
case 'override':
if (!arg1 || !arg2) {
printLine('Usage: override [attacker_ip] [kill_code]', 'line-error');
break;
}
if (currentHost !== s.vaultIp) {
triggerPenalty(10, 'Override must be executed directly from the Core Vault.');
break;
}
if (!servers[s.vaultIp].firewallBlocked) {
triggerPenalty(12, 'OVERRIDE BLOCKED: Active outbound C2 connection detected. Block attacker IP with ufw.');
break;
}
if (servers[s.vaultIp].malwareAlive) {
triggerPenalty(12, 'OVERRIDE BLOCKED: Malicious wiper daemon still locking memory.');
break;
}
if (arg1 === s.attackerIp && arg2 === s.killCode) {
endGame(true);
} else {
triggerPenalty(15, 'OVERRIDE REJECTED: Invalid attacker IP or kill code.');
}
break;
case 'clear':
outputEl.innerHTML = '';
break;
default:
triggerPenalty(2, cmd + ': command not found');
}
}
// Only focus input on a plain click, NOT when highlighting/selecting text
terminalEl.addEventListener('click', () => {
  const selectedText = window.getSelection().toString();
  if (!selectedText) {
    inputEl.focus();
  }
});

// Up & Down Arrow Keys to cycle through command history
inputEl.addEventListener('keydown', (e) => {
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    if (commandHistory.length === 0) return;
    if (historyIndex > 0) {
      historyIndex--;
    } else {
      historyIndex = 0;
    }
    inputEl.value = commandHistory.at(historyIndex);
  } else if (e.key === 'ArrowDown') {
    e.preventDefault();
    if (historyIndex === -1) return;
    if (historyIndex < commandHistory.length - 1) {
      historyIndex++;
      inputEl.value = commandHistory.at(historyIndex);
    } else {
      historyIndex = -1;
      inputEl.value = '';
    }
  }
});

formEl.addEventListener('submit', (e) => {
  e.preventDefault();
  if (gameOver) return;

  const value = inputEl.value.trim();
  if (!value) return;

  // Save command to history
  commandHistory.push(value);
  historyIndex = -1;

  printLine(promptLabelEl.textContent + ' ' + value, 'line-muted');
  inputEl.value = '';
  handleCommand(value);
});

printLine('=== ZERO_TRACE v3.0 // ENTERPRISE INCIDENT RESPONSE ===', 'line-purple');

printLine('==================================================================', 'line-purple');
printLine('SITUATION: A threat actor has breached our internal network and', 'line-white');
printLine('           launched a memory-locking wiper inside the Core Vault.', 'line-white');
printLine('OBJECTIVE: Trace the attacker across 4 servers, sever their C2', 'line-white');
printLine('           connection, purge the malware, and execute override.', 'line-white');
printLine('-----------------------------------------------------------------', 'line-purple');
printLine('COMMANDS : Type "ls" to inspect local files, "map" to view the', 'line-muted');
printLine('           network topology, or "help" for your cyber toolkit.', 'line-muted');
printLine('==================================================================', 'line-purple');
startTimer();
