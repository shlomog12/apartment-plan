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

-- שמות המשתמשים והסיסמאות לא נגישים מבחוץ: אין מדיניות גישה, והכול עובר דרך פונקציות.
alter table app_users enable row level security;
alter table plans enable row level security;

drop policy if exists "everyone reads plans" on plans;
create policy "everyone reads plans" on plans for select to anon, authenticated using (true);

revoke all on app_users from anon, authenticated;
revoke insert, update, delete on plans from anon, authenticated;
grant select (id, owner, title, objs, versions, created_at, updated_at, deleted) on plans to anon, authenticated;

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

create or replace function app_login(p_name text, p_pass text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare n text;
begin
  select name into n from app_users where lower(name) = lower(btrim(coalesce(p_name, ''))) and pass = p_pass;
  if n is null then return jsonb_build_object('ok', false, 'error', 'bad_login'); end if;
  return jsonb_build_object('ok', true, 'name', n);
end $$;

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
    insert into plans(owner, title, objs) values (p_name, t, p_objs) returning * into r;
    return jsonb_build_object('ok', true, 'id', r.id, 'updated_at', r.updated_at);
  end if;
  select * into r from plans where id = p_id for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if r.owner <> p_name then return jsonb_build_object('ok', false, 'error', 'not_owner'); end if;
  if p_expected is not null and r.updated_at <> p_expected then
    return jsonb_build_object('ok', false, 'error', 'conflict', 'updated_at', r.updated_at);
  end if;
  if lower(r.title) <> lower(t) and exists (select 1 from plans where owner = p_name and lower(title) = lower(t) and not deleted and id <> p_id) then
    return jsonb_build_object('ok', false, 'error', 'title_exists');
  end if;
  update plans set
    versions = (select coalesce(jsonb_agg(e order by i), '[]'::jsonb) from (
      select e, i from jsonb_array_elements(jsonb_build_array(jsonb_build_object('ts', r.updated_at, 'objs', r.objs)) || r.versions)
        with ordinality as t(e, i) order by i limit 5) s),
    objs = p_objs, title = t, updated_at = clock_timestamp(), deleted = false
  where id = p_id returning * into r;
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

grant execute on function app_register(text, text) to anon, authenticated;
grant execute on function app_login(text, text) to anon, authenticated;
grant execute on function app_save(text, text, uuid, text, jsonb, timestamptz) to anon, authenticated;
grant execute on function app_delete(text, text, uuid, boolean) to anon, authenticated;
revoke execute on function app_check(text, text) from public, anon, authenticated;
