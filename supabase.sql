-- תוכנית הדירה: הגדרת מסד הנתונים ב-Supabase
-- מדביקים את כל הקובץ ב-SQL Editor ולוחצים Run. בטוח להריץ יותר מפעם אחת.

create table if not exists app_users (
  name text primary key,
  pass text not null,
  created_at timestamptz not null default now()
);

create table if not exists plans (
  id uuid primary key default gen_random_uuid(),
  owner text not null references app_users(name) on update cascade,
  title text not null,
  objs jsonb not null,
  versions jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted boolean not null default false
);

-- Visibility: 'public' = everyone (also without an account); 'private' = the owner
-- and the users in plan_shares. New plans are private.
alter table plans add column if not exists visibility text not null default 'private';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'plans_visibility_chk') then
    alter table plans add constraint plans_visibility_chk check (visibility in ('public', 'private'));
  end if;
end $$;

create table if not exists plan_shares (
  plan_id uuid not null references plans(id) on delete cascade,
  user_name text not null references app_users(name) on update cascade on delete cascade,
  created_at timestamptz not null default now(),
  primary key (plan_id, user_name)
);
create index if not exists plan_shares_user_idx on plan_shares(user_name);
-- can_edit: the user may save changes to the plan (not share it, change its visibility or delete it).
alter table plan_shares add column if not exists can_edit boolean not null default false;
alter table plans add column if not exists updated_by text;

-- Version history: every cloud save adds a row; the newest 50 per plan are kept.
create table if not exists plan_versions (
  id bigserial primary key,
  plan_id uuid not null references plans(id) on delete cascade,
  title text not null,
  objs jsonb not null,
  saved_by text,
  created_at timestamptz not null default now()
);
create index if not exists plan_versions_plan_idx on plan_versions(plan_id, created_at desc);

create table if not exists app_migrations (
  name text primary key,
  applied_at timestamptz not null default now()
);

-- One-time migration: plans that existed before sharing was added become private
-- and shared with every user that exists at that moment. Runs once only, so
-- re-running this file later does not share new plans or new users.
do $$ begin
  if not exists (select 1 from app_migrations where name = 'share-existing-plans') then
    update plans set visibility = 'private';
    insert into plan_shares(plan_id, user_name)
      select p.id, u.name from plans p cross join app_users u where u.name <> p.owner
      on conflict do nothing;
    insert into app_migrations(name) values ('share-existing-plans');
  end if;
end $$;

-- One-time migration: copy the current content and the older 'versions' column into plan_versions.
do $$ begin
  if not exists (select 1 from app_migrations where name = 'versions-table') then
    insert into plan_versions(plan_id, title, objs, saved_by, created_at)
      select p.id, p.title, e->'objs', p.owner, coalesce((e->>'ts')::timestamptz, p.updated_at)
      from plans p, jsonb_array_elements(p.versions) e
      where jsonb_typeof(e->'objs') = 'array';
    insert into plan_versions(plan_id, title, objs, saved_by, created_at)
      select id, title, objs, owner, updated_at from plans;
    update plans set updated_by = owner where updated_by is null;
    insert into app_migrations(name) values ('versions-table');
  end if;
end $$;

-- Nothing is readable directly from outside: no policies, no table grants.
-- Every read and write goes through the functions below, which check the user.
alter table app_users enable row level security;
alter table plans enable row level security;
alter table plan_shares enable row level security;
alter table app_migrations enable row level security;
alter table plan_versions enable row level security;

drop policy if exists "everyone reads plans" on plans;

revoke all on app_users from anon, authenticated;
revoke all on plans from anon, authenticated;
revoke all on plan_shares from anon, authenticated;
revoke all on app_migrations from anon, authenticated;
revoke all on plan_versions from anon, authenticated;

create or replace function app_check(p_name text, p_pass text) returns boolean
language sql security definer set search_path = public as $$
  select exists (select 1 from app_users where name = p_name and pass = p_pass);
$$;

create or replace function app_register(p_name text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  p_name := btrim(coalesce(p_name, ''));
  if length(p_name) < 1 or length(p_name) > 40 then return jsonb_build_object('ok', false, 'error', 'bad_name'); end if;
  if length(coalesce(p_pass, '')) < 2 or length(p_pass) > 40 then return jsonb_build_object('ok', false, 'error', 'bad_pass'); end if;
  if exists (select 1 from app_users where lower(name) = lower(p_name)) then
    return jsonb_build_object('ok', false, 'error', 'exists');
  end if;
  insert into app_users(name, pass) values (p_name, p_pass);
  return jsonb_build_object('ok', true, 'name', p_name);
end $$;

-- Errors: 'no_user' when no account has this name, 'wrong_pass' when the name exists
-- but the password does not match. Revealing that a name exists adds nothing new:
-- app_register already answers 'exists', and logged-in users can list all names to share with.
create or replace function app_login(p_name text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n text; pw text;
begin
  select name, pass into n, pw from app_users where lower(name) = lower(btrim(coalesce(p_name, '')));
  if n is null then return jsonb_build_object('ok', false, 'error', 'no_user'); end if;
  if pw is distinct from p_pass then return jsonb_build_object('ok', false, 'error', 'wrong_pass'); end if;
  return jsonb_build_object('ok', true, 'name', n);
end $$;

-- The user's role on a plan: 'owner', 'edit', 'view', or null (cannot see it). p_user null = not logged in.
create or replace function app_role(p_user text, p_id uuid) returns text
language sql stable security definer set search_path = public as $$
  select case
    when p.owner = p_user then 'owner'
    when p.deleted then null
    when exists (select 1 from plan_shares s where s.plan_id = p.id and s.user_name = p_user and s.can_edit) then 'edit'
    when p.visibility = 'public' or exists (select 1 from plan_shares s where s.plan_id = p.id and s.user_name = p_user) then 'view'
  end
  from plans p where p.id = p_id;
$$;

-- Adds a history row and keeps only the newest 50 for the plan.
create or replace function app_add_version(p_id uuid, p_title text, p_objs jsonb, p_by text, p_at timestamptz) returns void
language sql security definer set search_path = public as $$
  insert into plan_versions(plan_id, title, objs, saved_by, created_at) values (p_id, p_title, p_objs, p_by, p_at);
  delete from plan_versions where plan_id = p_id and id not in (
    select id from plan_versions where plan_id = p_id order by created_at desc, id desc limit 50);
$$;

create or replace function app_save(p_name text, p_pass text, p_id uuid, p_title text, p_objs jsonb, p_expected timestamptz)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare r plans%rowtype; t text;
begin
  if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  t := btrim(coalesce(p_title, ''));
  if length(t) < 1 or length(t) > 80 then return jsonb_build_object('ok', false, 'error', 'bad_title'); end if;
  if jsonb_typeof(p_objs) <> 'array' or pg_column_size(p_objs) > 2000000 then
    return jsonb_build_object('ok', false, 'error', 'bad_plan');
  end if;
  if p_id is null then
    if exists (select 1 from plans where owner = p_name and lower(title) = lower(t) and not deleted) then
      return jsonb_build_object('ok', false, 'error', 'title_exists');
    end if;
    insert into plans(owner, title, objs, updated_by) values (p_name, t, p_objs, p_name) returning * into r;
    perform app_add_version(r.id, t, p_objs, p_name, r.updated_at);
    return jsonb_build_object('ok', true, 'id', r.id, 'updated_at', r.updated_at);
  end if;
  select * into r from plans where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if r.owner <> p_name and app_role(p_name, p_id) is distinct from 'edit' then
    return jsonb_build_object('ok', false, 'error', 'not_owner');
  end if;
  if p_expected is not null and r.updated_at <> p_expected then
    return jsonb_build_object('ok', false, 'error', 'conflict', 'updated_at', r.updated_at);
  end if;
  if lower(r.title) <> lower(t) and exists (select 1 from plans where owner = r.owner and lower(title) = lower(t) and not deleted and id <> p_id) then
    return jsonb_build_object('ok', false, 'error', 'title_exists');
  end if;
  update plans set objs = p_objs, title = t, updated_at = clock_timestamp(), updated_by = p_name,
    deleted = case when r.owner = p_name then false else deleted end
  where id = p_id returning * into r;
  perform app_add_version(r.id, t, p_objs, p_name, r.updated_at);
  return jsonb_build_object('ok', true, 'id', r.id, 'updated_at', r.updated_at);
end $$;

create or replace function app_delete(p_name text, p_pass text, p_id uuid, p_deleted boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare o text;
begin
  if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  select owner into o from plans where id = p_id;
  if o is null then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if o <> p_name then return jsonb_build_object('ok', false, 'error', 'not_owner'); end if;
  update plans set deleted = p_deleted where id = p_id;
  return jsonb_build_object('ok', true);
end $$;

-- Can this user (null = not logged in) see this plan?
create or replace function app_can_see(p_user text, p_id uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select app_role(p_user, p_id) is not null;
$$;

-- Plans this user may see. p_name null = not logged in: public plans only.
-- 'shared' = shared with this user; 'share_count' is filled for the owner only.
create or replace function app_list(p_name text, p_pass text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare u text;
begin
  if p_name is not null then
    if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
    u := p_name;
  end if;
  return jsonb_build_object('ok', true, 'plans', coalesce((
    select jsonb_agg(to_jsonb(x) order by x.updated_at desc) from (
      select p.id, p.owner, p.title, p.updated_at, p.updated_by, p.deleted, p.visibility, app_role(u, p.id) as role,
        exists (select 1 from plan_shares s where s.plan_id = p.id and s.user_name = u) as shared,
        case when p.owner = u then (select count(*) from plan_shares s where s.plan_id = p.id) end as share_count
      from plans p
      where app_can_see(u, p.id)
      order by p.updated_at desc
      limit 500) x), '[]'::jsonb));
end $$;

-- One plan with its content. Previous versions are returned to the owner only.
create or replace function app_get(p_name text, p_pass text, p_id uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare u text; r plans%rowtype;
begin
  if p_name is not null then
    if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
    u := p_name;
  end if;
  if not app_can_see(u, p_id) then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  select * into r from plans where id = p_id;
  return jsonb_build_object('ok', true, 'plan', jsonb_build_object(
    'id', r.id, 'owner', r.owner, 'title', r.title, 'objs', r.objs, 'updated_at', r.updated_at,
    'visibility', r.visibility, 'role', app_role(u, p_id), 'updated_by', r.updated_by,
    'versions', '[]'::jsonb));
end $$;

-- History list (without content) for the owner and editors.
create or replace function app_versions(p_name text, p_pass text, p_id uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  if app_role(p_name, p_id) is distinct from 'owner' and app_role(p_name, p_id) is distinct from 'edit' then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;
  return jsonb_build_object('ok', true, 'versions', coalesce((
    select jsonb_agg(jsonb_build_object('id', v.id, 'title', v.title, 'saved_by', v.saved_by, 'created_at', v.created_at)
      order by v.created_at desc, v.id desc)
    from plan_versions v where v.plan_id = p_id), '[]'::jsonb));
end $$;

-- One version's content, for the owner and editors.
create or replace function app_version_get(p_name text, p_pass text, p_vid bigint) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v plan_versions%rowtype;
begin
  if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  select * into v from plan_versions where id = p_vid;
  if not found or (app_role(p_name, v.plan_id) is distinct from 'owner' and app_role(p_name, v.plan_id) is distinct from 'edit') then
    return jsonb_build_object('ok', false, 'error', 'not_found');
  end if;
  return jsonb_build_object('ok', true, 'version', jsonb_build_object(
    'id', v.id, 'plan_id', v.plan_id, 'title', v.title, 'objs', v.objs, 'saved_by', v.saved_by, 'created_at', v.created_at));
end $$;

-- For the owner's share screen: visibility, who it is shared with, and every other user.
create or replace function app_share_get(p_name text, p_pass text, p_id uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare o text; v text;
begin
  if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  select owner, visibility into o, v from plans where id = p_id;
  if o is null then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if o <> p_name then return jsonb_build_object('ok', false, 'error', 'not_owner'); end if;
  return jsonb_build_object('ok', true, 'visibility', v,
    'shared', coalesce((select jsonb_agg(user_name order by lower(user_name)) from plan_shares where plan_id = p_id), '[]'::jsonb),
    'editors', coalesce((select jsonb_agg(user_name order by lower(user_name)) from plan_shares where plan_id = p_id and can_edit), '[]'::jsonb),
    'users', coalesce((select jsonb_agg(name order by lower(name)) from app_users where name <> o), '[]'::jsonb));
end $$;

-- The owner sets visibility, the full list of users the plan is shared with,
-- and which of them may edit (p_editors, a subset of p_users).
drop function if exists app_share_set(text, text, uuid, text, text[]);
create or replace function app_share_set(p_name text, p_pass text, p_id uuid, p_visibility text, p_users text[], p_editors text[] default null)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare o text;
begin
  if not app_check(p_name, p_pass) then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  if p_visibility not in ('public', 'private') then return jsonb_build_object('ok', false, 'error', 'bad_visibility'); end if;
  select owner into o from plans where id = p_id for update;
  if o is null then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if o <> p_name then return jsonb_build_object('ok', false, 'error', 'not_owner'); end if;
  update plans set visibility = p_visibility where id = p_id;
  delete from plan_shares where plan_id = p_id and not (user_name = any (coalesce(p_users, '{}')));
  insert into plan_shares(plan_id, user_name)
    select p_id, u.name from app_users u where u.name = any (coalesce(p_users, '{}')) and u.name <> o
    on conflict do nothing;
  update plan_shares set can_edit = (user_name = any (coalesce(p_editors, '{}'))) where plan_id = p_id;
  return jsonb_build_object('ok', true, 'visibility', p_visibility,
    'share_count', (select count(*) from plan_shares where plan_id = p_id));
end $$;

grant execute on function app_register(text, text) to anon, authenticated;
grant execute on function app_list(text, text) to anon, authenticated;
grant execute on function app_get(text, text, uuid) to anon, authenticated;
grant execute on function app_share_get(text, text, uuid) to anon, authenticated;
grant execute on function app_share_set(text, text, uuid, text, text[], text[]) to anon, authenticated;
grant execute on function app_versions(text, text, uuid) to anon, authenticated;
grant execute on function app_version_get(text, text, bigint) to anon, authenticated;
revoke execute on function app_can_see(text, uuid) from public, anon, authenticated;
revoke execute on function app_role(text, uuid) from public, anon, authenticated;
revoke execute on function app_add_version(uuid, text, jsonb, text, timestamptz) from public, anon, authenticated;
grant execute on function app_login(text, text) to anon, authenticated;
grant execute on function app_save(text, text, uuid, text, jsonb, timestamptz) to anon, authenticated;
grant execute on function app_delete(text, text, uuid, boolean) to anon, authenticated;
revoke execute on function app_check(text, text) from public, anon, authenticated;
