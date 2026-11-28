-- Keep the unmanaged Django CallCheck model aligned with the Supabase table.
-- Run this in the Supabase SQL Editor if these columns are not already present.

alter table public.call_checks
    add column if not exists claimed_institution varchar(160) not null default '';

alter table public.call_checks
    add column if not exists caller_demands jsonb not null default '[]'::jsonb;

create index if not exists idx_call_checks_user_created_at
    on public.call_checks (user_id, created_at desc);
