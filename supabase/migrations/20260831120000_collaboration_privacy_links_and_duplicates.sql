-- Privacidad, enlaces solicitados y protección contra pedidos duplicados.
-- Esta migración presupone el esquema de colaboradores ya desplegado.

alter table public.collaborator_applications
  add column if not exists requested_slug text;

alter table public.collaborator_applications
  drop constraint if exists collaborator_applications_requested_slug_format;

alter table public.collaborator_applications
  add constraint collaborator_applications_requested_slug_format
  check (requested_slug is null or requested_slug ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$');

create unique index if not exists collaborators_slug_lower_unique
  on public.collaborators (lower(slug));

create unique index if not exists collaborators_promo_code_upper_unique
  on public.collaborators (upper(promo_code));

create unique index if not exists sales_order_reference_upper_unique
  on public.sales (upper(order_reference));

create index if not exists sales_collaborator_created_at_idx
  on public.sales (collaborator_id, created_at desc);

create index if not exists commission_payments_collaborator_paid_at_idx
  on public.commission_payments (collaborator_id, paid_at desc);

create or replace function public.is_collaboration_identifier_available(p_value text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    p_value is not null
    and lower(trim(p_value)) ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'
    and not exists (
      select 1 from public.collaborators
      where lower(slug) = lower(trim(p_value))
         or lower(promo_code) = lower(trim(p_value))
    )
    and not exists (
      select 1 from public.collaborator_applications
      where status = 'pending'
        and lower(requested_slug) = lower(trim(p_value))
    );
$$;

revoke all on function public.is_collaboration_identifier_available(text) from public;
grant execute on function public.is_collaboration_identifier_available(text) to anon, authenticated;

create or replace function public.handle_collaborator_signup()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  requested_name text;
  requested_link text;
begin
  if coalesce(new.raw_user_meta_data ->> 'registration_type', '') <> 'collaborator' then
    return new;
  end if;

  requested_name := trim(coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  requested_link := lower(trim(coalesce(new.raw_user_meta_data ->> 'requested_slug', '')));

  if char_length(requested_name) < 2 then
    raise exception 'El nombre de la solicitud no es válido.';
  end if;

  if requested_link !~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$' then
    raise exception 'El enlace solicitado no es válido.';
  end if;

  if not public.is_collaboration_identifier_available(requested_link) then
    raise exception 'El enlace solicitado ya está utilizado o pendiente.';
  end if;

  insert into public.collaborator_applications (user_id, full_name, email, requested_slug)
  values (new.id, left(requested_name, 80), lower(new.email), requested_link);
  return new;
end;
$$;

revoke all on function public.handle_collaborator_signup() from public, anon, authenticated;

drop function if exists public.approve_collaborator_application(uuid, text, numeric, integer, integer, integer);

create or replace function public.approve_collaborator_application(
  p_application_id uuid,
  p_slug text,
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
  normalized_slug text;
  normalized_promo text;
begin
  if not public.is_admin() then
    raise exception 'Solo un administrador puede aprobar solicitudes.';
  end if;

  if p_discount_percent < 0 or p_discount_percent > 100
     or p_unit_commission_cents < 0
     or p_bonus_every_units < 1
     or p_bonus_cents < 0 then
    raise exception 'Las condiciones económicas no son válidas.';
  end if;

  select * into application
  from public.collaborator_applications
  where id = p_application_id
  for update;

  if not found or application.status <> 'pending' then
    raise exception 'La solicitud no existe o ya ha sido revisada.';
  end if;

  normalized_slug := lower(trim(p_slug));
  normalized_promo := upper(trim(p_promo_code));

  if normalized_slug !~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$' then
    raise exception 'El enlace no tiene un formato válido.';
  end if;
  if normalized_promo !~ '^[A-Z0-9_-]{3,30}$' then
    raise exception 'El código promocional no tiene un formato válido.';
  end if;
  if exists (
    select 1 from public.collaborators
    where lower(slug) = normalized_slug
       or upper(promo_code) = normalized_promo
  ) then
    raise exception 'El enlace o el código promocional ya está utilizado.';
  end if;

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
    application.user_id, application.full_name, application.email,
    normalized_slug, normalized_promo, p_discount_percent,
    p_unit_commission_cents, p_bonus_every_units, p_bonus_cents, true, current_date
  ) returning * into collaborator;

  update public.collaborator_applications
  set status = 'approved', reviewed_at = now(), reviewed_by = auth.uid(),
      review_note = '', requested_slug = normalized_slug
  where id = application.id;

  return collaborator;
end;
$$;

revoke all on function public.approve_collaborator_application(uuid, text, text, numeric, integer, integer, integer)
  from public, anon;
grant execute on function public.approve_collaborator_application(uuid, text, text, numeric, integer, integer, integer)
  to authenticated;

-- RLS: la interfaz puede solicitar listas completas, pero la base de datos solo
-- devuelve las filas del usuario actual. La administración conserva acceso total.
alter table public.profiles enable row level security;
alter table public.collaborators enable row level security;
alter table public.sales enable row level security;
alter table public.commission_payments enable row level security;

-- Las políticas permisivas se combinan con OR. Para que una política antigua
-- no abra datos de otros colaboradores, sustituimos todas las de estas tablas.
do $$
declare
  policy_row record;
begin
  for policy_row in
    select schemaname, tablename, policyname
    from pg_policies
    where schemaname = 'public'
      and tablename in ('profiles', 'collaborators', 'sales', 'commission_payments')
  loop
    execute format('drop policy if exists %I on %I.%I',
      policy_row.policyname, policy_row.schemaname, policy_row.tablename);
  end loop;
end;
$$;

alter view public.collaborator_summary set (security_invoker = true);

drop policy if exists nortepack_profiles_private on public.profiles;
create policy nortepack_profiles_private on public.profiles
for select to authenticated
using (id = auth.uid() or public.is_admin());

drop policy if exists nortepack_collaborators_private on public.collaborators;
create policy nortepack_collaborators_private on public.collaborators
for select to authenticated
using (user_id = auth.uid() or public.is_admin());

drop policy if exists nortepack_sales_private on public.sales;
create policy nortepack_sales_private on public.sales
for select to authenticated
using (
  public.is_admin()
  or exists (
    select 1 from public.collaborators c
    where c.id = sales.collaborator_id and c.user_id = auth.uid()
  )
);

drop policy if exists nortepack_payments_private on public.commission_payments;
create policy nortepack_payments_private on public.commission_payments
for select to authenticated
using (
  public.is_admin()
  or exists (
    select 1 from public.collaborators c
    where c.id = commission_payments.collaborator_id and c.user_id = auth.uid()
  )
);

-- Los cambios económicos no se conceden al cliente. Se realizan mediante las
-- funciones administrativas del servidor, que vuelven a comprobar is_admin().
revoke insert, update, delete on public.collaborators from authenticated;
revoke insert, update, delete on public.sales from authenticated;
revoke insert, update, delete on public.commission_payments from authenticated;

-- Alta automática de una venta atribuida al abrir WhatsApp. La referencia es
-- idempotente: repetir exactamente el mismo pedido no crea otra comisión.
create or replace function public.create_attributed_sale(
  p_ref text,
  p_order_reference text,
  p_items jsonb,
  p_source text default 'link'
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  target_collaborator public.collaborators;
  existing_sale public.sales;
  item jsonb;
  product public.products;
  quantity integer;
  normalized_items jsonb := '[]'::jsonb;
  total_units integer := 0;
  gross_cents integer := 0;
  discount_cents integer := 0;
  created_id uuid;
begin
  if p_order_reference !~ '^NP-[A-Z0-9-]{8,40}$' then
    raise exception 'La referencia del pedido no es válida.';
  end if;
  if p_source not in ('link', 'code', 'manual') then
    raise exception 'El origen de la atribución no es válido.';
  end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) < 1
     or jsonb_array_length(p_items) > 20 then
    raise exception 'El pedido debe contener entre 1 y 20 productos.';
  end if;

  select * into target_collaborator
  from public.collaborators
  where active = true
    and (lower(slug) = lower(trim(p_ref)) or upper(promo_code) = upper(trim(p_ref)))
  limit 1;
  if not found then
    raise exception 'La colaboración no existe o está desactivada.';
  end if;

  select * into existing_sale from public.sales
  where upper(order_reference) = upper(p_order_reference);
  if found then
    if existing_sale.collaborator_id <> target_collaborator.id then
      raise exception 'La referencia ya está asociada a otro pedido.';
    end if;
    return existing_sale.id;
  end if;

  for item in select value from jsonb_array_elements(p_items)
  loop
    quantity := coalesce((item ->> 'qty')::integer, 0);
    if quantity < 1 or quantity > 99 then
      raise exception 'La cantidad de un producto no es válida.';
    end if;
    select * into product from public.products
    where sku = item ->> 'sku' and active = true;
    if not found then
      raise exception 'Uno de los productos ya no está disponible.';
    end if;
    total_units := total_units + quantity;
    gross_cents := gross_cents + product.unit_price_cents * quantity;
    normalized_items := normalized_items || jsonb_build_array(jsonb_build_object(
      'sku', product.sku, 'name', product.name, 'color', product.color,
      'qty', quantity, 'unit_price_cents', product.unit_price_cents
    ));
  end loop;

  discount_cents := round(gross_cents * target_collaborator.discount_percent / 100.0);

  insert into public.sales (
    order_reference, collaborator_id, items, units, returned_units, status,
    gross_amount_cents, discount_amount_cents, net_amount_cents,
    unit_commission_cents, eligible_units, base_commission_cents,
    attribution_source, internal_notes, confirmed_at
  ) values (
    upper(p_order_reference), target_collaborator.id, normalized_items,
    total_units, 0, 'confirmed', gross_cents, discount_cents,
    gross_cents - discount_cents, target_collaborator.unit_commission_cents,
    total_units, total_units * target_collaborator.unit_commission_cents,
    p_source, 'Registrado automáticamente al abrir WhatsApp', now()
  ) returning id into created_id;

  return created_id;
end;
$$;

revoke all on function public.create_attributed_sale(text, text, jsonb, text) from public;
grant execute on function public.create_attributed_sale(text, text, jsonb, text) to anon, authenticated;

create or replace function public.admin_create_sale(
  p_collaborator_id uuid,
  p_order_reference text,
  p_items jsonb,
  p_source text default 'manual',
  p_status text default 'confirmed',
  p_internal_notes text default ''
)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare collaborator_slug text; created_id uuid;
begin
  if not public.is_admin() then raise exception 'Solo un administrador puede crear ventas.'; end if;
  select slug into collaborator_slug from public.collaborators where id=p_collaborator_id;
  if not found then raise exception 'El colaborador no existe.'; end if;
  created_id := public.create_attributed_sale(collaborator_slug,p_order_reference,p_items,p_source);
  update public.sales set internal_notes=left(trim(coalesce(p_internal_notes,'')),500) where id=created_id;
  if p_status='pending' then perform public.admin_update_sale(created_id,'pending',0); end if;
  return created_id;
end;
$$;

revoke all on function public.admin_create_sale(uuid, text, jsonb, text, text, text) from public, anon;
grant execute on function public.admin_create_sale(uuid, text, jsonb, text, text, text) to authenticated;

create or replace function public.admin_update_sale(
  p_sale_id uuid,
  p_status text,
  p_returned_units integer default 0
)
returns public.sales
language plpgsql
security definer
set search_path = public
as $$
declare
  changed public.sales;
begin
  if not public.is_admin() then
    raise exception 'Solo un administrador puede modificar ventas.';
  end if;
  if p_status not in ('pending', 'confirmed', 'cancelled', 'returned') then
    raise exception 'El estado no es válido.';
  end if;

  update public.sales
  set status = p_status,
      returned_units = case when p_status = 'returned' then units else p_returned_units end,
      eligible_units = case
        when p_status = 'confirmed' then greatest(units - p_returned_units, 0)
        else 0
      end,
      base_commission_cents = case
        when p_status = 'confirmed' then greatest(units - p_returned_units, 0) * unit_commission_cents
        else 0
      end,
      confirmed_at = case when p_status = 'confirmed' then coalesce(confirmed_at, now()) else confirmed_at end,
      updated_at = now()
  where id = p_sale_id
    and p_returned_units between 0 and units
  returning * into changed;

  if not found then
    raise exception 'La venta no existe o las unidades devueltas no son válidas.';
  end if;
  return changed;
end;
$$;

revoke all on function public.admin_update_sale(uuid, text, integer) from public, anon;
grant execute on function public.admin_update_sale(uuid, text, integer) to authenticated;

create or replace function public.admin_set_collaborator_status(p_collaborator_id uuid, p_active boolean)
returns public.collaborators
language plpgsql
security definer
set search_path = public
as $$
declare changed public.collaborators;
begin
  if not public.is_admin() then raise exception 'Solo un administrador puede cambiar este estado.'; end if;
  update public.collaborators
  set active = p_active, ended_at = case when p_active then null else now() end, updated_at = now()
  where id = p_collaborator_id returning * into changed;
  if not found then raise exception 'El colaborador no existe.'; end if;
  return changed;
end;
$$;

revoke all on function public.admin_set_collaborator_status(uuid, boolean) from public, anon;
grant execute on function public.admin_set_collaborator_status(uuid, boolean) to authenticated;

create or replace function public.admin_record_payment(
  p_collaborator_id uuid,
  p_amount_cents integer,
  p_paid_at timestamptz,
  p_note text default ''
)
returns public.commission_payments
language plpgsql
security definer
set search_path = public
as $$
declare created public.commission_payments;
begin
  if not public.is_admin() then raise exception 'Solo un administrador puede registrar pagos.'; end if;
  if p_amount_cents <= 0 then raise exception 'El importe debe ser mayor que cero.'; end if;
  insert into public.commission_payments(collaborator_id,amount_cents,paid_at,note,created_by)
  values(p_collaborator_id,p_amount_cents,coalesce(p_paid_at,now()),left(trim(coalesce(p_note,'')),300),auth.uid())
  returning * into created;
  return created;
end;
$$;

revoke all on function public.admin_record_payment(uuid, integer, timestamptz, text) from public, anon;
grant execute on function public.admin_record_payment(uuid, integer, timestamptz, text) to authenticated;
