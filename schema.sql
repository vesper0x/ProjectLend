-- ============================================================
-- Apollo whitelist — points & referrals schema (Supabase/Postgres)
-- ============================================================
-- Run this once in the Supabase SQL editor on a fresh project.
-- It assumes Supabase Auth is enabled (auth.users already exists)
-- with the X/Twitter OAuth 2.0 provider and Email OTP turned on
-- in Authentication → Providers.
--
-- Design principle: points are never stored as a mutable number.
-- They are a SUM over an append-only ledger, so a bug can be
-- audited ("why does this account have 450 points?") instead of
-- silently drifting. Every write that matters goes through a
-- SECURITY DEFINER function, not a raw INSERT from the client —
-- that's what makes "one referral credit per person, ever" and
-- "no self-referral" actually enforceable instead of advisory.
-- ============================================================

-- ── profiles ──────────────────────────────────────────────────
-- One row per real person. id = auth.users.id, so a profile only
-- exists once someone has actually authenticated (via X or email).
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  handle      text,                          -- display name, e.g. X handle or email local-part
  marketing_consent boolean not null default false,  -- explicit opt-in only; never default true
  marketing_email   text check (marketing_email ~* '^[^\s@]+@[^\s@]+\.[a-z]{2,}$'),
                     -- separate from the login identity on purpose: an X-only
                     -- account has no email at all, so consent needs its own
                     -- destination to actually mean anything
  consented_at       timestamptz,                     -- when they opted in; cleared if they opt out
  created_at  timestamptz not null default now()
);

-- ── referral_codes ───────────────────────────────────────────
-- One code per account. Uppercase, unique, 3–16 chars. The
-- account_id UNIQUE constraint means claiming a new code retires
-- the old one rather than letting someone hoard several.
create table public.referral_codes (
  code        text primary key
                check (code ~ '^[A-Z0-9-]{3,16}$'),
  account_id  uuid not null unique references public.profiles(id) on delete cascade,
  created_at  timestamptz not null default now()
);

-- ── referrals ─────────────────────────────────────────────────
-- referred_id is the PRIMARY KEY, not just unique-constrained —
-- that's the actual mechanism that makes "credited once, ever"
-- true at the database level, not just in application logic.
create table public.referrals (
  referred_id  uuid primary key references public.profiles(id) on delete cascade,
  referrer_id  uuid not null references public.profiles(id) on delete cascade,
  created_at   timestamptz not null default now(),
  constraint no_self_referral check (referrer_id <> referred_id)
);

-- ── points_ledger ─────────────────────────────────────────────
-- Append-only. Never UPDATE or DELETE a row here from application
-- code — if a correction is needed, insert a reversing entry.
create table public.points_ledger (
  id                bigint generated always as identity primary key,
  account_id        uuid not null references public.profiles(id) on delete cascade,
  reason            text not null check (reason in ('signup', 'referral_bonus', 'referred_bonus', 'post_bonus')),
  amount            int  not null,
  related_account_id uuid references public.profiles(id),
  created_at        timestamptz not null default now()
);

-- one signup bonus per account, enforced by the DB, not the app
create unique index one_signup_bonus_per_account
  on public.points_ledger (account_id)
  where reason = 'signup';

-- one post bonus per account, ever — same pattern as signup.
-- If you later want to reward multiple verified posts, drop this
-- index rather than loosen the check in application code.
create unique index one_post_bonus_per_account
  on public.points_ledger (account_id)
  where reason = 'post_bonus';

create index points_ledger_account_idx on public.points_ledger (account_id);

-- fast lookup for "who consented" when syncing to Resend/Loops/etc.
create index profiles_marketing_consent_idx
  on public.profiles (id)
  where marketing_consent = true;


-- ── social_posts ─────────────────────────────────────────────
-- A submission is just a claim until it's checked. status starts
-- 'pending' and only the verifier (running as service_role, see
-- the Edge Function below) is allowed to move it to 'verified' or
-- 'rejected' — regular users can insert their own pending row and
-- read their own rows, nothing more (see RLS below).
--
-- Note on service_role: this file never GRANTs table access to it
-- explicitly, because on a real Supabase project service_role
-- already bypasses RLS by default — that's Supabase's own
-- configuration, not something this schema sets up. (A plain
-- Postgres instance with a same-named role you created yourself,
-- e.g. for local testing, will NOT have that bypass unless you
-- grant it — don't mistake that for a bug in this file.)
create table public.social_posts (
  id            bigint generated always as identity primary key,
  account_id    uuid not null references public.profiles(id) on delete cascade,
  post_url      text not null check (post_url ~ '^https?://(x\.com|twitter\.com)/'),
  status        text not null default 'pending' check (status in ('pending','verified','rejected')),
  reason        text,                      -- why it was rejected, for the UI to show
  submitted_at  timestamptz not null default now(),
  checked_at    timestamptz
);

create index social_posts_account_idx on public.social_posts (account_id);


-- Aggregated totals — this is what the client actually reads.
-- It never exposes individual ledger rows (see RLS below), so
-- nobody can see *why* another account has the points it has,
-- only the totals everyone already sees on the leaderboard.
create view public.points_totals as
  select account_id, coalesce(sum(amount), 0)::int as points
  from public.points_ledger
  group by account_id;

create view public.referral_counts as
  select referrer_id as account_id, count(*)::int as referrals
  from public.referrals
  group by referrer_id;

create view public.leaderboard as
  select
    p.id,
    coalesce(p.handle, 'anon') as handle,
    coalesce(pt.points, 0)      as points,
    coalesce(rc.referrals, 0)   as referrals,
    rank() over (order by coalesce(pt.points, 0) desc, p.created_at asc) as rank
  from public.profiles p
  left join public.points_totals   pt on pt.account_id = p.id
  left join public.referral_counts rc on rc.account_id = p.id;


-- ============================================================
-- Row Level Security
-- ============================================================
alter table public.profiles       enable row level security;
alter table public.referral_codes enable row level security;
alter table public.referrals      enable row level security;
alter table public.points_ledger  enable row level security;
alter table public.social_posts   enable row level security;

-- profiles: handle is public (leaderboard needs it); people can
-- only edit their own row, and only via the functions below.
create policy "profiles are publicly readable"
  on public.profiles for select using (true);
create policy "users manage only their own profile"
  on public.profiles for insert with check (auth.uid() = id);
create policy "users update only their own profile"
  on public.profiles for update using (auth.uid() = id);

-- referral_codes: public read (needed to resolve ?ref=CODE before
-- the visitor has an account), owner-only write.
create policy "referral codes are publicly readable"
  on public.referral_codes for select using (true);
create policy "users claim only their own code"
  on public.referral_codes for insert with check (auth.uid() = account_id);
create policy "users update only their own code"
  on public.referral_codes for update using (auth.uid() = account_id);

-- referrals: readable only by the two people involved. No direct
-- INSERT policy at all — the only path in is join_whitelist(),
-- which runs as SECURITY DEFINER and bypasses RLS deliberately.
create policy "see referrals you're part of"
  on public.referrals for select
  using (auth.uid() = referrer_id or auth.uid() = referred_id);

-- points_ledger: readable only by the account it belongs to.
-- Nobody can browse anyone else's ledger — the public leaderboard
-- reads from the aggregated view instead, which has no RLS
-- because it carries no per-event detail to leak.
create policy "see only your own ledger"
  on public.points_ledger for select using (auth.uid() = account_id);

-- social_posts: users can see their own submissions and create a
-- new pending one. They can never set status themselves — the
-- WITH CHECK forces every self-inserted row to start 'pending',
-- and there is deliberately no UPDATE policy for regular users at
-- all, so only service_role (the verifier) can move a row to
-- 'verified' or 'rejected'.
create policy "see only your own post submissions"
  on public.social_posts for select using (auth.uid() = account_id);
create policy "submit only your own pending post"
  on public.social_posts for insert
  with check (auth.uid() = account_id and status = 'pending');


-- ============================================================
-- RPC functions — the only way points or referrals get written
-- ============================================================

-- Call once, right after a person authenticates for the first
-- time. Idempotent: calling it again is a harmless no-op instead
-- of erroring or double-crediting. Writes only — call
-- get_my_stats() right after to read back the result.
--
-- p_marketing_consent: pass true/false to record this person's
-- current choice (their latest answer always wins — a later "no"
-- must overwrite an earlier "yes"). Pass null to leave whatever
-- is already on file untouched, e.g. on a login call where the
-- checkbox wasn't shown again.
--
-- p_marketing_email: where to actually send those updates. Needed
-- separately from the login identity because signing in with X
-- gives no email at all — without this, a checked box would have
-- nowhere to send anything.
create or replace function public.join_whitelist(
  p_referral_code text default null,
  p_marketing_consent boolean default null,
  p_marketing_email text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_referrer uuid;
  v_code text;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;

  -- create the profile if this is a first-time signup
  insert into public.profiles (id, handle)
  values (v_uid, split_part(coalesce(auth.jwt() ->> 'email', 'member'), '@', 1))
  on conflict (id) do nothing;

  -- record this call's consent choice, if one was given. Always
  -- honour the most recent answer — never leave a stale "yes" in
  -- place after someone has said no. An email is only ever stored
  -- alongside an explicit "yes" — never attach one to a "no".
  if p_marketing_consent is not null then
    update public.profiles
    set marketing_consent = p_marketing_consent,
        marketing_email = case when p_marketing_consent then coalesce(p_marketing_email, marketing_email) else null end,
        consented_at = case when p_marketing_consent then now() else null end
    where id = v_uid;
  end if;

  -- signup bonus — the partial unique index makes this safe to
  -- attempt on every call without ever double-crediting
  insert into public.points_ledger (account_id, reason, amount)
  values (v_uid, 'signup', 100)
  on conflict do nothing;

  -- issue a default referral code if this account doesn't have one
  if not exists (select 1 from public.referral_codes where account_id = v_uid) then
    v_code := 'APOLLO-' || upper(substr(md5(v_uid::text || now()::text), 1, 4));
    insert into public.referral_codes (code, account_id) values (v_code, v_uid);
  end if;

  -- referral credit — only on this account's first join, and only
  -- if the code is real and not their own
  if p_referral_code is not null and not exists (select 1 from public.referrals where referred_id = v_uid) then
    select account_id into v_referrer
    from public.referral_codes
    where code = upper(trim(p_referral_code));

    if v_referrer is not null and v_referrer <> v_uid then
      insert into public.referrals (referred_id, referrer_id)
      values (v_uid, v_referrer)
      on conflict do nothing;

      if found then
        insert into public.points_ledger (account_id, reason, amount, related_account_id)
        values (v_referrer, 'referral_bonus', 50, v_uid);
        insert into public.points_ledger (account_id, reason, amount, related_account_id)
        values (v_uid, 'referred_bonus', 50, v_referrer);
      end if;
    end if;
  end if;
end;
$$;

-- Read-your-own-stats — call this after join_whitelist(), and any
-- time the page loads with an existing session, to populate the
-- dashboard honestly from the database instead of guessing.
create or replace function public.get_my_stats()
returns table(points int, referrals int, rank bigint, code text)
language sql
security definer
set search_path = public
stable
as $$
  select l.points, l.referrals, l.rank, rc.code
  from public.leaderboard l
  join public.referral_codes rc on rc.account_id = l.id
  where l.id = auth.uid();
$$;

-- Claim or change a custom referral code. Uniqueness is enforced
-- by the primary key on referral_codes — this function just gives
-- a clean error instead of a raw constraint violation, and retires
-- the caller's previous code in the same transaction.
create or replace function public.claim_referral_code(p_code text)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_code text := upper(trim(p_code));
begin
  if v_uid is null then raise exception 'not authenticated'; end if;
  if v_code !~ '^[A-Z0-9-]{3,16}$' then
    raise exception 'codes must be 3-16 characters: letters, numbers, dashes';
  end if;
  if exists (select 1 from public.referral_codes where code = v_code and account_id <> v_uid) then
    raise exception 'that code is already taken';
  end if;

  delete from public.referral_codes where account_id = v_uid;
  insert into public.referral_codes (code, account_id) values (v_code, v_uid);
  return v_code;
end;
$$;

-- Change marketing consent on its own, any time — this is what an
-- unsubscribe link or an account-settings toggle should call. It
-- does not touch points, referrals, or anything else. p_email is
-- optional: pass it when someone opts in from settings with a new
-- address; omit it (or pass null) for a plain unsubscribe.
create or replace function public.set_marketing_consent(p_consent boolean, p_email text default null)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  update public.profiles
  set marketing_consent = p_consent,
      marketing_email = case when p_consent then coalesce(p_email, marketing_email) else null end,
      consented_at = case when p_consent then now() else null end
  where id = auth.uid();
end;
$$;

-- Top of the leaderboard for the public page — capped, and reads
-- from the view so it carries no per-event ledger detail.
create or replace function public.get_leaderboard(p_limit int default 10)
returns setof public.leaderboard
language sql
stable
as $$
  select * from public.leaderboard order by rank asc limit p_limit;
$$;


-- ============================================================
-- "Share to earn 300" — submission + verification
-- ============================================================
-- Two functions, deliberately split by who is allowed to call them:
--
--  submit_post()          — anyone signed in. Just records a claim.
--  credit_verified_post() — service_role ONLY. This is what
--                           actually pays out points, and it can't
--                           be reached from the browser no matter
--                           what the client sends, because REVOKE
--                           below strips execute from everyone else.
--
-- The actual checking — does the post exist, does it contain this
-- account's referral code — happens outside Postgres, in a
-- Supabase Edge Function (see verify_post_edge_function.ts). That
-- function fetches the post via X's public oEmbed endpoint, then
-- calls credit_verified_post() with the service-role key once it's
-- satisfied. Postgres itself never makes the outbound HTTP call.

create or replace function public.submit_post(p_url text)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_id  bigint;
begin
  if v_uid is null then raise exception 'not authenticated'; end if;

  if exists (select 1 from public.points_ledger where account_id = v_uid and reason = 'post_bonus') then
    raise exception 'already credited for a verified post';
  end if;
  if exists (select 1 from public.social_posts where account_id = v_uid and status = 'pending') then
    raise exception 'you already have a submission awaiting review';
  end if;

  insert into public.social_posts (account_id, post_url)
  values (v_uid, trim(p_url))
  returning id into v_id;

  return v_id;
end;
$$;

create or replace function public.credit_verified_post(p_post_id bigint, p_ok boolean, p_reason text default null)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_account uuid;
begin
  select account_id into v_account from public.social_posts where id = p_post_id and status = 'pending';
  if v_account is null then
    raise exception 'no pending submission with that id';
  end if;

  update public.social_posts
  set status = case when p_ok then 'verified' else 'rejected' end,
      reason = p_reason,
      checked_at = now()
  where id = p_post_id;

  if p_ok then
    insert into public.points_ledger (account_id, reason, amount)
    values (v_account, 'post_bonus', 300)
    on conflict do nothing;  -- the partial unique index is the real guard; this just avoids a hard error
  end if;
end;
$$;

-- Lock credit_verified_post down to the verifier only. submit_post
-- stays callable by any signed-in user (that's the default for a
-- SECURITY DEFINER function owned by the project, so no grant is
-- needed there — this REVOKE/GRANT pair is what matters).
revoke execute on function public.credit_verified_post(bigint, boolean, text) from public, authenticated, anon;
grant  execute on function public.credit_verified_post(bigint, boolean, text) to service_role;
