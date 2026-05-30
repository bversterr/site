create table if not exists threat_events (
  id             uuid        default gen_random_uuid() primary key,
  created_at     timestamptz default now(),
  title          text        not null,
  description    text,
  severity       text        not null check (severity in ('critical','high','medium','low')),
  category       text        not null check (category in ('malware','phishing','ransomware','apt','botnet','insider','other')),
  source_ip      text,
  source_country text,
  resolved       boolean     default false,
  resolved_at    timestamptz
);

create index on threat_events (severity);
create index on threat_events (created_at desc);
alter table threat_events enable row level security;
create policy "Authenticated users only" on threat_events
  for all using (auth.role() = 'authenticated');


create table if not exists iocs (
  id          uuid  default gen_random_uuid() primary key,
  created_at  timestamptz default now(),
  type        text  not null check (type in ('ip','domain','hash','url')),
  value       text  not null unique,
  threat_name text,
  severity    text  default 'medium' check (severity in ('critical','high','medium','low')),
  source      text,
  active      boolean default true
);

create index on iocs (type);
create index on iocs (active);
alter table iocs enable row level security;
create policy "Authenticated users only" on iocs
  for all using (auth.role() = 'authenticated');


create table if not exists vulnerabilities (
  id          uuid  default gen_random_uuid() primary key,
  created_at  timestamptz default now(),
  title       text  not null,
  cve_id      text,
  cvss_score  numeric(3,1),
  severity    text  not null check (severity in ('critical','high','medium','low')),
  affected    text  not null,
  description text,
  status      text  default 'open' check (status in ('open','in_progress','patched'))
);

create index on vulnerabilities (severity);
create index on vulnerabilities (status);
alter table vulnerabilities enable row level security;
create policy "Authenticated users only" on vulnerabilities
  for all using (auth.role() = 'authenticated');


create table if not exists audit_log (
  id          uuid  default gen_random_uuid() primary key,
  created_at  timestamptz default now(),
  user_email  text,
  event_type  text  not null check (event_type in ('auth','block','detect','policy','system')),
  severity    text  default 'info' check (severity in ('critical','high','medium','low','info')),
  actor       text,
  event       text  not null,
  outcome     text  check (outcome in ('success','blocked','warning','failed')),
  detail      jsonb default '{}'::jsonb
);

create index on audit_log (event_type);
create index on audit_log (created_at desc);
alter table audit_log enable row level security;
create policy "Authenticated users only" on audit_log
  for all using (auth.role() = 'authenticated');


insert into threat_events (title, description, severity, category, source_ip, source_country) values
  ('BlackCat Ransomware Detected', 'Ransomware payload found on WORKSTATION-07', 'critical', 'ransomware', '185.220.101.47', 'RU'),
  ('Phishing Campaign Intercepted', 'BEC attempt targeting finance team', 'high', 'phishing', '103.79.77.200', 'CN'),
  ('Botnet C2 Callback Blocked', 'Outbound connection to known C2 server', 'high', 'botnet', '91.108.56.211', 'RU'),
  ('Suspicious Login Attempt', 'Brute force detected on SSH port 22', 'medium', 'other', '45.33.219.14', 'US');

insert into iocs (type, value, threat_name, severity, source) values
  ('ip',     '185.220.101.47',             'BlackCat C2',    'critical', 'CISA'),
  ('ip',     '103.79.77.200',              'APT41 Infra',    'critical', 'MISP'),
  ('domain', 'secure-login-update.ru',     'Phishing',       'high',     'PhishTank'),
  ('hash',   'a3f7c9b2d1e4f8a0c5b6d2e9f1', 'BlackCat.exe',   'critical', 'VirusTotal'),
  ('url',    'http://185.220.101.47/gate.php','Malware Dropper','high',   'OTX');

insert into vulnerabilities (title, cve_id, cvss_score, severity, affected, description, status) values
  ('Windows OLE Remote Code Execution', 'CVE-2025-21298', 9.8, 'critical', 'Windows Workstations', 'RCE via crafted OLE object', 'open'),
  ('Fortinet FortiOS Auth Bypass',      'CVE-2024-55591', 9.6, 'critical', 'Perimeter Firewall',   'Auth bypass via crafted CSF proxy request', 'in_progress'),
  ('PostgreSQL SQL Injection',          'CVE-2025-1094',  8.1, 'high',     'Database Server',      'SQL injection via incorrect neutralisation', 'open');

insert into audit_log (user_email, event_type, severity, actor, event, outcome, detail) values
  ('batman@benjaminverster.co.za', 'auth',   'info',     'batman@benjaminverster.co.za', 'Admin login',                 'success', '{"ip":"196.14.22.108","location":"Cape Town"}'),
  (null,                           'block',  'critical', 'FIREWALL-AUTO',                'C2 callback blocked',         'blocked', '{"ip":"185.220.101.47","port":4444}'),
  (null,                           'detect', 'critical', 'EDR-AGENT',                   'Ransomware payload detected', 'blocked', '{"host":"WORKSTATION-07","file":"svchost32.exe"}'),
  (null,                           'system', 'info',     'SYSTEM',                      'Threat intel feeds synced',   'success', '{"new_iocs":1847}');
```

---

### `blueghost-backend/routes/__init__.py`
```
