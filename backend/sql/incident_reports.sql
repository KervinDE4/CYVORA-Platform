-- CYVORA incident reporting storage.
-- Run this once in the Supabase SQL Editor for the project database.
-- Django maps this table with managed=False, so Django migrations will not create it.

create table if not exists public.incident_reports (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    module_type varchar(30) not null
        check (module_type in ('threat_scan', 'call_trust')),
    source_record_id uuid null,
    target_value text not null,
    target_fingerprint varchar(64) not null,
    verdict varchar(30) not null,
    risk_level varchar(30) not null default 'HIGH RISK',
    notes text not null default '',
    created_at timestamptz not null default now()
);

create unique index if not exists uq_incident_reports_user_module_target
    on public.incident_reports (user_id, module_type, target_fingerprint);

create index if not exists idx_incident_reports_created_at
    on public.incident_reports (created_at desc);

alter table public.incident_reports enable row level security;

do $$
begin
    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'incident_reports'
          and policyname = 'Users view own incident reports'
    ) then
        create policy "Users view own incident reports"
            on public.incident_reports
            for select to authenticated
            using (auth.uid() = user_id);
    end if;

    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'incident_reports'
          and policyname = 'Users create own incident reports'
    ) then
        create policy "Users create own incident reports"
            on public.incident_reports
            for insert to authenticated
            with check (auth.uid() = user_id);
    end if;
end
$$;
