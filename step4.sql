-- =====================================================
-- Phase 4: 알림센터 / 코멘트 좋아요·답글 / 카테고리 필터
--          / 프로필 공유 / 신고·차단 / 관리자 화면
-- 기존 테이블은 그대로 둔 채 필요한 것만 추가해요.
-- =====================================================

-- ===== 0. 관리자 판별 함수 =====
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(auth.jwt() ->> 'email', '') = 'wbhsjsneie90smd@gmail.com';
$$;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- ===== 1. 포트폴리오: 카테고리 / 정지(suspend) =====
alter table public.portfolios add column if not exists category text;
alter table public.portfolios add column if not exists is_suspended boolean not null default false;

grant update (category) on public.portfolios to authenticated;

drop policy if exists "portfolios_select" on public.portfolios;
create policy "portfolios_select" on public.portfolios for select to authenticated
  using (not is_suspended or user_id = auth.uid() or public.is_admin());

-- 관리자는 모든 포트폴리오를 수정(정지 처리)할 수 있어야 함
drop policy if exists "portfolios_update" on public.portfolios;
create policy "portfolios_update" on public.portfolios for update to authenticated
  using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());

-- ===== 2. 코멘트: 답글(parent_id) =====
alter table public.comments add column if not exists parent_id bigint references public.comments(id) on delete cascade;
create index if not exists comments_parent_idx on public.comments (parent_id);

-- 관리자는 아무 코멘트나 지울 수 있음
drop policy if exists "comments_delete" on public.comments;
create policy "comments_delete" on public.comments for delete to authenticated
  using (author_id = auth.uid() or public.is_admin());

-- ===== 3. 코멘트 좋아요 =====
create table if not exists public.comment_likes (
  comment_id bigint not null references public.comments(id) on delete cascade,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (comment_id, user_id)
);
alter table public.comment_likes enable row level security;

drop policy if exists "comment_likes_select" on public.comment_likes;
drop policy if exists "comment_likes_insert" on public.comment_likes;
drop policy if exists "comment_likes_delete" on public.comment_likes;
create policy "comment_likes_select" on public.comment_likes for select to authenticated using (true);
create policy "comment_likes_insert" on public.comment_likes for insert to authenticated
  with check (user_id = auth.uid());
create policy "comment_likes_delete" on public.comment_likes for delete to authenticated
  using (user_id = auth.uid());

grant select, insert, delete on public.comment_likes to authenticated;

-- ===== 4. 차단 =====
create table if not exists public.blocks (
  blocker_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  blocked_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);
alter table public.blocks enable row level security;

drop policy if exists "blocks_select" on public.blocks;
drop policy if exists "blocks_insert" on public.blocks;
drop policy if exists "blocks_delete" on public.blocks;
create policy "blocks_select" on public.blocks for select to authenticated
  using (blocker_id = auth.uid());
create policy "blocks_insert" on public.blocks for insert to authenticated
  with check (blocker_id = auth.uid());
create policy "blocks_delete" on public.blocks for delete to authenticated
  using (blocker_id = auth.uid());

grant select, insert, delete on public.blocks to authenticated;

-- ===== 5. 신고 =====
create table if not exists public.reports (
  id bigint generated always as identity primary key,
  reporter_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  target_user_id uuid not null references auth.users(id) on delete cascade,
  reason text not null check (char_length(reason) between 1 and 500),
  status text not null default 'pending' check (status in ('pending', 'resolved', 'dismissed')),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index if not exists reports_status_idx on public.reports (status);
alter table public.reports enable row level security;

drop policy if exists "reports_select" on public.reports;
drop policy if exists "reports_insert" on public.reports;
drop policy if exists "reports_update" on public.reports;
create policy "reports_select" on public.reports for select to authenticated
  using (reporter_id = auth.uid() or public.is_admin());
create policy "reports_insert" on public.reports for insert to authenticated
  with check (reporter_id = auth.uid() and target_user_id <> auth.uid());
create policy "reports_update" on public.reports for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

grant select, insert on public.reports to authenticated;
grant update (status, resolved_at) on public.reports to authenticated;

-- ===== 6. 알림 =====
create table if not exists public.notifications (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  type text not null,              -- like / comment / comment_reply / comment_like / friend_request / friend_accept / message
  actor_id uuid references auth.users(id) on delete set null,
  actor_name text,
  portfolio_id uuid,
  comment_id bigint,
  body text,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists notifications_user_idx on public.notifications (user_id, created_at desc);
alter table public.notifications enable row level security;

drop policy if exists "notifications_select" on public.notifications;
drop policy if exists "notifications_update" on public.notifications;
create policy "notifications_select" on public.notifications for select to authenticated
  using (user_id = auth.uid());
create policy "notifications_update" on public.notifications for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- 클라이언트가 직접 insert/delete 하지 못하게 막음 (트리거로만 생성)
revoke insert, delete on public.notifications from authenticated;
grant select on public.notifications to authenticated;
grant update (is_read) on public.notifications to authenticated;

create or replace function public.mark_notifications_read()
returns void
language sql
security definer
set search_path = public
as $$
  update public.notifications set is_read = true where user_id = auth.uid() and is_read = false;
$$;
revoke all on function public.mark_notifications_read() from public, anon;
grant execute on function public.mark_notifications_read() to authenticated;

-- ----- 알림 트리거: 좋아요 -----
create or replace function public.notify_like()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare actor_name text;
begin
  if new.user_id = new.portfolio_id then return new; end if;   -- 본인이 본인 글에 좋아요 → 알림 생략
  select coalesce(display_name, name, '누군가') into actor_name from public.portfolios where user_id = new.user_id;
  insert into public.notifications (user_id, type, actor_id, actor_name, portfolio_id, body)
  values (new.portfolio_id, 'like', new.user_id, actor_name, new.portfolio_id, '회원님의 포트폴리오를 좋아해요.');
  return new;
end;
$$;
drop trigger if exists trg_notify_like on public.likes;
create trigger trg_notify_like after insert on public.likes
  for each row execute function public.notify_like();

-- ----- 알림 트리거: 코멘트 / 답글 -----
create or replace function public.notify_comment()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  owner_id uuid;
  parent_author uuid;
begin
  if new.parent_id is null then
    select user_id into owner_id from public.portfolios where user_id = new.portfolio_id;
    if owner_id is not null and owner_id <> new.author_id then
      insert into public.notifications (user_id, type, actor_id, actor_name, portfolio_id, comment_id, body)
      values (owner_id, 'comment', new.author_id, new.author_name, new.portfolio_id, new.id, new.text);
    end if;
  else
    select author_id into parent_author from public.comments where id = new.parent_id;
    if parent_author is not null and parent_author <> new.author_id then
      insert into public.notifications (user_id, type, actor_id, actor_name, portfolio_id, comment_id, body)
      values (parent_author, 'comment_reply', new.author_id, new.author_name, new.portfolio_id, new.id, new.text);
    end if;
  end if;
  return new;
end;
$$;
drop trigger if exists trg_notify_comment on public.comments;
create trigger trg_notify_comment after insert on public.comments
  for each row execute function public.notify_comment();

-- ----- 알림 트리거: 코멘트 좋아요 -----
create or replace function public.notify_comment_like()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  c_author uuid;
  c_portfolio uuid;
  actor_name text;
begin
  select author_id, portfolio_id into c_author, c_portfolio from public.comments where id = new.comment_id;
  if c_author is null or c_author = new.user_id then return new; end if;
  select coalesce(display_name, name, '누군가') into actor_name from public.portfolios where user_id = new.user_id;
  insert into public.notifications (user_id, type, actor_id, actor_name, portfolio_id, comment_id, body)
  values (c_author, 'comment_like', new.user_id, actor_name, c_portfolio, new.comment_id, '회원님의 코멘트를 좋아해요.');
  return new;
end;
$$;
drop trigger if exists trg_notify_comment_like on public.comment_likes;
create trigger trg_notify_comment_like after insert on public.comment_likes
  for each row execute function public.notify_comment_like();

-- ----- 알림 트리거: 친구 요청 / 수락 -----
create or replace function public.notify_friendship()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare actor_name text;
begin
  if tg_op = 'INSERT' then
    select coalesce(display_name, name, '누군가') into actor_name from public.portfolios where user_id = new.requester_id;
    insert into public.notifications (user_id, type, actor_id, actor_name, body)
    values (new.addressee_id, 'friend_request', new.requester_id, actor_name, '친구 요청을 보냈어요.');
  elsif tg_op = 'UPDATE' and new.status = 'accepted' and old.status <> 'accepted' then
    select coalesce(display_name, name, '누군가') into actor_name from public.portfolios where user_id = new.addressee_id;
    insert into public.notifications (user_id, type, actor_id, actor_name, body)
    values (new.requester_id, 'friend_accept', new.addressee_id, actor_name, '친구 요청을 수락했어요.');
  end if;
  return new;
end;
$$;
drop trigger if exists trg_notify_friendship on public.friendships;
create trigger trg_notify_friendship after insert or update on public.friendships
  for each row execute function public.notify_friendship();

-- ----- 알림 트리거: 메시지 (대화가 이미 수락 상태일 때만) -----
create or replace function public.notify_message()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  conv public.conversations%rowtype;
  recipient uuid;
  actor_name text;
begin
  select * into conv from public.conversations where id = new.conversation_id;
  if conv.status <> 'accepted' then return new; end if;
  recipient := case when conv.user_a = new.sender_id then conv.user_b else conv.user_a end;
  select coalesce(display_name, name, '누군가') into actor_name from public.portfolios where user_id = new.sender_id;
  insert into public.notifications (user_id, type, actor_id, actor_name, body)
  values (recipient, 'message', new.sender_id, actor_name, '새 메시지를 보냈어요.');
  return new;
end;
$$;
drop trigger if exists trg_notify_message on public.messages;
create trigger trg_notify_message after insert on public.messages
  for each row execute function public.notify_message();

-- ===== 7. 차단 반영: 친구 요청 / 메시지 보내기 =====
drop policy if exists "friendships_insert" on public.friendships;
create policy "friendships_insert" on public.friendships for insert to authenticated
  with check (
    requester_id = auth.uid()
    and status = 'pending'
    and exists (select 1 from public.portfolios p where p.user_id = auth.uid())
    and exists (select 1 from public.portfolios p where p.user_id = addressee_id)
    and not exists (select 1 from public.blocks b where
      (b.blocker_id = auth.uid() and b.blocked_id = addressee_id) or
      (b.blocker_id = addressee_id and b.blocked_id = auth.uid()))
  );

create or replace function public.send_message(p_to uuid, p_body text)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  me uuid := auth.uid();
  ua uuid;
  ub uuid;
  conv public.conversations%rowtype;
  are_friends boolean;
  sent_count int;
  new_id bigint;
begin
  if me is null then
    raise exception 'not_authenticated';
  end if;
  if p_to is null or p_to = me then
    raise exception 'invalid_recipient';
  end if;

  p_body := btrim(coalesce(p_body, ''));
  if char_length(p_body) < 1 or char_length(p_body) > 2000 then
    raise exception 'invalid_message';
  end if;

  if not exists (select 1 from public.portfolios where user_id = me) then
    raise exception 'need_portfolio';
  end if;
  if not exists (select 1 from public.portfolios where user_id = p_to) then
    raise exception 'invalid_recipient';
  end if;

  if exists (select 1 from public.blocks b where
      (b.blocker_id = me and b.blocked_id = p_to) or (b.blocker_id = p_to and b.blocked_id = me)) then
    raise exception 'blocked';
  end if;

  ua := least(me, p_to);
  ub := greatest(me, p_to);

  select exists (
    select 1 from public.friendships f
    where f.status = 'accepted'
      and least(f.requester_id, f.addressee_id) = ua
      and greatest(f.requester_id, f.addressee_id) = ub
  ) into are_friends;

  select * into conv from public.conversations where user_a = ua and user_b = ub for update;

  if not found then
    insert into public.conversations (user_a, user_b, initiator_id, status)
    values (ua, ub, me, case when are_friends then 'accepted' else 'pending' end)
    returning * into conv;
  else
    if conv.status <> 'accepted' and are_friends then
      update public.conversations set status = 'accepted' where id = conv.id;
      conv.status := 'accepted';
    end if;

    if conv.status = 'pending' then
      if conv.initiator_id = me then
        select count(*) into sent_count from public.messages where conversation_id = conv.id;
        if sent_count >= 1 then
          raise exception 'request_pending';
        end if;
      else
        raise exception 'must_accept';
      end if;
    elsif conv.status = 'declined' then
      if conv.initiator_id = me then
        raise exception 'request_declined';
      else
        update public.conversations set status = 'accepted' where id = conv.id;
      end if;
    end if;
  end if;

  insert into public.messages (conversation_id, sender_id, body)
  values (conv.id, me, p_body)
  returning id into new_id;

  update public.conversations set updated_at = now() where id = conv.id;
  return new_id;
end;
$$;

-- ===== 8. 관리자 RPC =====
create or replace function public.admin_stats()
returns table (
  total_users bigint,
  total_portfolios bigint,
  total_comments bigint,
  total_likes bigint,
  pending_reports bigint,
  suspended_portfolios bigint
)
language sql
stable
security definer
set search_path = public
as $$
  select
    (select count(*) from auth.users),
    (select count(*) from public.portfolios),
    (select count(*) from public.comments),
    (select count(*) from public.likes),
    (select count(*) from public.reports where status = 'pending'),
    (select count(*) from public.portfolios where is_suspended)
  where public.is_admin();
$$;
revoke all on function public.admin_stats() from public, anon;
grant execute on function public.admin_stats() to authenticated;

create or replace function public.admin_list_reports(p_status text default 'pending')
returns table (
  id bigint, reporter_id uuid, reporter_name text,
  target_user_id uuid, target_name text, target_suspended boolean,
  reason text, status text, created_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select r.id, r.reporter_id, coalesce(rp.display_name, rp.name, '알 수 없음'),
         r.target_user_id, coalesce(tp.display_name, tp.name, '알 수 없음'), coalesce(tp.is_suspended, false),
         r.reason, r.status, r.created_at
  from public.reports r
  left join public.portfolios rp on rp.user_id = r.reporter_id
  left join public.portfolios tp on tp.user_id = r.target_user_id
  where public.is_admin() and r.status = p_status
  order by r.created_at desc;
$$;
revoke all on function public.admin_list_reports(text) from public, anon;
grant execute on function public.admin_list_reports(text) to authenticated;

create or replace function public.admin_resolve_report(p_id bigint, p_status text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'not_authorized'; end if;
  if p_status not in ('resolved', 'dismissed') then raise exception 'invalid_status'; end if;
  update public.reports set status = p_status, resolved_at = now() where id = p_id;
end;
$$;
revoke all on function public.admin_resolve_report(bigint, text) from public, anon;
grant execute on function public.admin_resolve_report(bigint, text) to authenticated;

create or replace function public.admin_delete_comment(p_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'not_authorized'; end if;
  delete from public.comments where id = p_id;
end;
$$;
revoke all on function public.admin_delete_comment(bigint) from public, anon;
grant execute on function public.admin_delete_comment(bigint) to authenticated;

create or replace function public.admin_set_suspended(p_user_id uuid, p_suspended boolean)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'not_authorized'; end if;
  update public.portfolios set is_suspended = p_suspended where user_id = p_user_id;
end;
$$;
revoke all on function public.admin_set_suspended(uuid, boolean) from public, anon;
grant execute on function public.admin_set_suspended(uuid, boolean) to authenticated;

-- =====================================================
-- 참고: 실시간(Realtime) 기능을 쓰려면 Supabase 대시보드에서
-- Database > Replication 메뉴로 가서
-- messages, notifications 테이블의 Realtime 토글을 켜주세요.
-- (켜지 않아도 앱은 자동 새로고침(폴링) 방식으로 정상 동작해요.)
-- =====================================================
