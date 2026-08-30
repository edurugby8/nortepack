-- Solicitudes de colaboradores con aprobación administrativa.
-- Registrarse nunca concede acceso a ventas, comisiones ni datos privados.

create table public.collaborator_applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  full_name text not null check (char_length(trim(full_name)) between 2 and 80),
  email text not null unique,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  review_note text not null default '' check (char_length(review_note) <= 300),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.collaborator_applications enable row level security;

create policy applications_select_own
on public.collaborator_applications
for select
to authenticated
using (user_id = auth.uid());

create policy applications_admin_all
on public.collaborator_applications
for all
to authenticated
using (public.is_admin())
with check (public.is_admin());

grant select on public.collaborator_applications to authenticated;

create trigger set_collaborator_applications_updated_at
before update on public.collaborator_applications
for each row execute function public.set_updated_at();

create or replace function public.handle_collaborator_signup()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_name text;
begin
  if coalesce(new.raw_user_meta_data ->> 'registration_type', '') <> 'collaborator' then
    return new;
  end if;

  requested_name := trim(coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  if char_length(requested_name) < 2 then
    requested_name := 'Colaborador';
  end if;

  insert into public.collaborator_applications (user_id, full_name, email)
  values (new.id, left(requested_name, 80), lower(new.email));

  return new;
end;
$$;

revoke all on function public.handle_collaborator_signup() from public, anon, authenticated;

create trigger on_auth_user_created_collaborator_application
after insert on auth.users
for each row execute function public.handle_collaborator_signup();

create or replace function public.approve_collaborator_application(
  p_application_id uuid,
  p_promo_code text,
  p_discount_percent numeric default 30,
  p_unit_commission_cents integer default 300,
  p_bonus_every_units integer default 8,
  p_bonus_cents integer default 3000
)
returns public.collaborators
language plpgsql
security definer
set search_path = public
as $$
declare
  application public.collaborator_applications;
  collaborator public.collaborators;
  generated_slug text;
  normalized_promo text;
begin
  if not public.is_admin() then
    raise exception 'Solo un administrador puede aprobar solicitudes.';
  end if;

  select * into application
  from public.collaborator_applications
  where id = p_application_id
  for update;

  if not found then
    raise exception 'La solicitud no existe.';
  end if;
  if application.status <> 'pending' then
    raise exception 'La solicitud ya ha sido revisada.';
  end if;

  normalized_promo := upper(trim(p_promo_code));
  if normalized_promo !~ '^[A-Z0-9_-]{3,30}$' then
    raise exception 'El código promocional no tiene un formato válido.';
  end if;

  generated_slug := trim(both '-' from regexp_replace(lower(split_part(application.email, '@', 1)), '[^a-z0-9]+', '-', 'g'));
  if char_length(generated_slug) < 2 then generated_slug := 'colaborador'; end if;
  generated_slug := left(generated_slug, 45) || '-' || left(replace(application.id::text, '-', ''), 8);

  insert into public.profiles (id, full_name, role)
  values (application.user_id, application.full_name, 'collaborator')
  on conflict (id) do update
  set full_name = excluded.full_name,
      role = excluded.role,
      updated_at = now();

  insert into public.collaborators (
    user_id, name, email, slug, promo_code, discount_percent,
    unit_commission_cents, bonus_every_units, bonus_cents, active, started_at
  ) values (
    application.user_id, application.full_name, application.email, generated_slug,
    normalized_promo, p_discount_percent, p_unit_commission_cents,
    p_bonus_every_units, p_bonus_cents, true, current_date
  ) returning * into collaborator;

  update public.collaborator_applications
  set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid(), review_note = ''
  where id = application.id;

  return collaborator;
end;
$$;

create or replace function public.reject_collaborator_application(
  p_application_id uuid,
  p_review_note text default ''
)
returns public.collaborator_applications
language plpgsql
security definer
set search_path = public
as $$
declare
  application public.collaborator_applications;
begin
  if not public.is_admin() then
    raise exception 'Solo un administrador puede revisar solicitudes.';
  end if;

  update public.collaborator_applications
  set status = 'rejected',
      review_note = left(trim(coalesce(p_review_note, '')), 300),
      reviewed_at = now(),
      reviewed_by = auth.uid()
  where id = p_application_id and status = 'pending'
  returning * into application;

  if not found then
    raise exception 'La solicitud no existe o ya ha sido revisada.';
  end if;

  return application;
end;
$$;

revoke all on function public.approve_collaborator_application(uuid, text, numeric, integer, integer, integer) from public, anon;
revoke all on function public.reject_collaborator_application(uuid, text) from public, anon;
grant execute on function public.approve_collaborator_application(uuid, text, numeric, integer, integer, integer) to authenticated;
grant execute on function public.reject_collaborator_application(uuid, text) to authenticated;
