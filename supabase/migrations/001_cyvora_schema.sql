-- ==========================================
-- 1. PROFILES (Linked to Supabase Auth)
-- ==========================================
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'user' check (role in ('user', 'moderator', 'admin')),
  secure_score integer not null default 50 check (secure_score >= 0 and secure_score <= 100),
  created_at timestamptz not null default now()
);

-- Automatically create a profile row whenever a new user signs up
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', 'CYVORA User'));
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ==========================================
-- 2. SCANS (Powers ThreatScan, CallTrust & Command Logs)
-- ==========================================
create table public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  module_type text not null check (module_type in ('threat_scan', 'call_trust')),
  input_type text not null check (input_type in ('url', 'text', 'screenshot', 'pdf', 'phone_check')),
  channel text check (channel in ('whatsapp', 'sms', 'email', 'telegram', 'social_dm', 'voice_call')),
  target_value text, -- e.g., URL, normalized phone number, or short sanitized snippet
  claimed_identity text, -- used in CallTrust (e.g., "FNB Eswatini")
  verdict text not null check (verdict in ('clean', 'suspicious', 'malicious', 'spoofed', 'inconclusive')),
  risk_score integer not null check (risk_score >= 0 and risk_score <= 100),
  headline text not null,
  summary text not null,
  indicators jsonb not null default '[]'::jsonb, -- stores array of red-flag breakdowns
  containment_steps jsonb not null default '[]'::jsonb, -- stores array of next steps
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

-- ==========================================
-- 3. SCAN ATTACHMENTS (Screenshots & PDFs metadata)
-- ==========================================
create table public.scan_attachments (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  storage_path text not null,
  mime_type text not null check (mime_type in ('image/png', 'image/jpeg', 'image/webp', 'application/pdf')),
  file_size_bytes integer not null check (file_size_bytes > 0 and file_size_bytes <= 5242880),
  created_at timestamptz not null default now()
);

-- ==========================================
-- 4. VERIFIED CONTACTS (Powers CallTrust Official Directory)
-- ==========================================
create table public.verified_contacts (
  id uuid primary key default gen_random_uuid(),
  organization_name text not null,
  category text not null check (category in ('bank', 'mobile_money', 'telco', 'government', 'utility')),
  official_phone text not null unique,
  official_website text,
  notes text,
  created_at timestamptz not null default now()
);

-- ==========================================
-- 5. SCAM REPORTS (Powers Report Intake Center)
-- ==========================================
create table public.scam_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  scan_id uuid references public.scans(id) on delete set null,
  category text not null check (category in ('caller_spoofing', 'sms_whatsapp_phishing', 'malicious_link', 'account_access', 'identity_theft')),
  offender_contact text, -- phone number, handle, or URL
  description text not null,
  status text not null default 'pending' check (status in ('pending', 'in_review', 'verified', 'rejected')),
  created_at timestamptz not null default now()
);

-- ==========================================
-- 6. THREAT ALERTS (Powers Live Threat Radar on Command Center)
-- ==========================================
create table public.threat_alerts (
  id uuid primary key default gen_random_uuid(),
  severity text not null check (severity in ('critical', 'suspicious', 'advisory')),
  title text not null,
  description text not null,
  region text not null default 'Eswatini',
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

-- ==========================================
-- 7. ACADEMY MODULES & PROGRESS (Powers CYVORA Academy)
-- ==========================================
create table public.academy_modules (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  category text not null,
  difficulty text not null check (difficulty in ('beginner', 'intermediate', 'advanced')),
  duration_mins integer not null default 10,
  summary text not null,
  content text not null,
  created_at timestamptz not null default now()
);

create table public.user_module_progress (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  module_id uuid not null references public.academy_modules(id) on delete cascade,
  status text not null default 'not_started' check (status in ('not_started', 'in_progress', 'completed')),
  progress_pct integer not null default 0 check (progress_pct >= 0 and progress_pct <= 100),
  updated_at timestamptz not null default now(),
  unique (user_id, module_id)
);

-- ==========================================
-- INDEXES FOR PERFORMANCE
-- ==========================================
create index idx_scans_user_id on public.scans(user_id);
create index idx_scans_created_at on public.scans(created_at desc);
create index idx_reports_user_id on public.scam_reports(user_id);
create index idx_reports_status on public.scam_reports(status);

-- ==========================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==========================================
alter table public.profiles enable row level security;
alter table public.scans enable row level security;
alter table public.scan_attachments enable row level security;
alter table public.verified_contacts enable row level security;
alter table public.scam_reports enable row level security;
alter table public.threat_alerts enable row level security;
alter table public.academy_modules enable row level security;
alter table public.user_module_progress enable row level security;

-- Profiles: users read/update only their own profile
create policy "Users view own profile" on public.profiles for select using (auth.uid() = id);
create policy "Users update own profile" on public.profiles for update using (auth.uid() = id);

-- Scans & Attachments: users access only their own records
create policy "Users view own scans" on public.scans for select using (auth.uid() = user_id);
create policy "Users insert own scans" on public.scans for insert with check (auth.uid() = user_id);
create policy "Users view own attachments" on public.scan_attachments for select using (auth.uid() = user_id);
create policy "Users insert own attachments" on public.scan_attachments for insert with check (auth.uid() = user_id);

-- Scam Reports: users see/create their own; moderators/admins see/update all
create policy "Users view own reports" on public.scam_reports for select using (auth.uid() = user_id);
create policy "Users create own reports" on public.scam_reports for insert with check (auth.uid() = user_id);
create policy "Moderators manage all reports" on public.scam_reports for all using (
  exists (select 1 from public.profiles where id = auth.uid() and role in ('moderator', 'admin'))
);

-- Reference Tables: any authenticated user can read
create policy "Authenticated read verified contacts" on public.verified_contacts for select to authenticated using (true);
create policy "Authenticated read active alerts" on public.threat_alerts for select to authenticated using (is_active = true);
create policy "Authenticated read academy modules" on public.academy_modules for select to authenticated using (true);

-- Academy Progress: users manage their own progress
create policy "Users manage own progress" on public.user_module_progress for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- ==========================================
-- STARTER SEED DATA (So UI has real Eswatini records immediately)
-- ==========================================
insert into public.verified_contacts (organization_name, category, official_phone, notes) values
  ('FNB Eswatini', 'bank', '+268 2518 6000', 'Official customer contact center'),
  ('Standard Bank Eswatini', 'bank', '+268 2405 6000', 'Official customer support line'),
  ('MTN MoMo Eswatini', 'mobile_money', '+268 7606 0999', 'Official mobile money helpline'),
  ('Eswatini Revenue Service', 'government', '+268 2406 4000', 'Official taxpayer contact line');

insert into public.threat_alerts (severity, title, description, region) values
  ('critical', 'Fake Mobile Money & Bank Verification Links', 'Fraudsters are sending urgent SMS/WhatsApp links claiming your account will be suspended unless you enter your PIN or OTP.', 'Eswatini'),
  ('suspicious', 'Impersonation Calls Claiming Accidental Transfers', 'Callers claim they sent mobile money by mistake and pressure victims to send funds back before checking real balances.', 'Eswatini');