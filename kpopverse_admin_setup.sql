-- KPOPVERSE: Supabase starter schema
-- Run this in Supabase SQL Editor only after creating your Supabase project.
-- IMPORTANT: Never put the Supabase service_role key in browser code.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique,
  display_name text,
  role text not null default 'user'
    check (role in ('user','moderator','admin','super_admin')),
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- Anyone signed in can read basic profiles.
create policy "Profiles are readable by authenticated users"
on public.profiles for select
to authenticated
using (true);

-- Users may create only their own profile, and cannot choose a privileged role.
create policy "Users create their own basic profile"
on public.profiles for insert
to authenticated
with check (auth.uid() = id and role = 'user');

-- Users may update their own display fields, but not their role.
-- Use a trigger to prevent role changes through normal client requests.
create or replace function public.prevent_role_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.role is distinct from old.role
     and auth.uid() is not null
     and auth.uid() <> old.id then
    raise exception 'Not allowed';
  end if;
  if new.role is distinct from old.role
     and auth.uid() = old.id then
    raise exception 'Users cannot change their own role';
  end if;
  return new;
end;
$$;

drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role
before update on public.profiles
for each row execute function public.prevent_role_change();

create policy "Users update their own profile"
on public.profiles for update
to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);

-- Helper function for checking trusted roles in policies.
create or replace function public.has_staff_role()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid()
      and role in ('moderator','admin','super_admin')
  );
$$;

-- Example protected admin-only table.
create table if not exists public.admin_audit_log (
  id bigint generated always as identity primary key,
  actor uuid not null references auth.users(id),
  action text not null,
  created_at timestamptz not null default now()
);
alter table public.admin_audit_log enable row level security;

create policy "Staff can read audit log"
on public.admin_audit_log for select
to authenticated
using (public.has_staff_role());

-- Create a profile automatically after a new user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, username, display_name, role)
  values (
    new.id,
    nullif(new.raw_user_meta_data->>'username',''),
    coalesce(nullif(new.raw_user_meta_data->>'display_name',''), 'KPOPVERSE Fan'),
    'user'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- SUPER ADMIN SETUP:
-- 1) Create/sign up your own account through the app first.
-- 2) In Supabase Dashboard > Authentication > Users, copy YOUR user's UUID.
-- 3) Replace YOUR_USER_UUID below and run this statement in SQL Editor.
-- 4) Never expose this SQL editor or service_role key to ordinary users.
-- update public.profiles
-- set role = 'super_admin'
-- where id = 'YOUR_USER_UUID'::uuid;

