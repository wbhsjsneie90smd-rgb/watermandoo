-- =====================================================
-- 친구 / 메시지 기능 (기존 테이블은 건드리지 않아요)
-- =====================================================

-- ===== 1. 친구 =====
create table if not exists public.friendships (
  id bigint generated always as identity primary key,
  requester_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  addressee_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted')),
  created_at timestamptz not null default now(),
  check (requester_id <> addressee_id)
);

-- A→B, B→A 를 같은 관계로 취급해서 중복 요청을 막음
create unique index if not exists friendships_pair_uniq
  on public.friendships (least(requester_id, addressee_id), greatest(requester_id, addressee_id));
create index if not exists friendships_addressee_idx on public.friendships (addressee_id);
create index if not exists friendships_requester_idx on public.friendships (requester_id);

-- ===== 2. 대화방 / 메시지 =====
create table if not exists public.conversations (
  id bigint generated always as identity primary key,
  user_a uuid not null references auth.users(id) on delete cascade,
  user_b uuid not null references auth.users(id) on delete cascade,
  initiator_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'declined')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (user_a < user_b),
  check (initiator_id in (user_a, user_b)),
  unique (user_a, user_b)
);
create index if not exists conversations_user_b_idx on public.conversations (user_b);

create table if not exists public.messages (
  id bigint generated always as identity primary key,
  conversation_id bigint not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 2000),
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists messages_conv_idx on public.messages (conversation_id, id);

-- ===== 3. 접근 규칙 (RLS) =====
alter table public.friendships enable row level security;
alter table public.conversations enable row level security;
alter table public.messages enable row level security;

drop policy if exists "friendships_select" on public.friendships;
drop policy if exists "friendships_insert" on public.friendships;
drop policy if exists "friendships_update" on public.friendships;
drop policy if exists "friendships_delete" on public.friendships;
create policy "friendships_select" on public.friendships for select to authenticated
  using (auth.uid() in (requester_id, addressee_id));
create policy "friendships_insert" on public.friendships for insert to authenticated
  with check (
    requester_id = auth.uid()
    and status = 'pending'
    and exists (select 1 from public.portfolios p where p.user_id = auth.uid())
    and exists (select 1 from public.portfolios p where p.user_id = addressee_id)
  );
create policy "friendships_update" on public.friendships for update to authenticated
  using (addressee_id = auth.uid()) with check (addressee_id = auth.uid());
create policy "friendships_delete" on public.friendships for delete to authenticated
  using (auth.uid() in (requester_id, addressee_id));

drop policy if exists "conversations_select" on public.conversations;
drop policy if exists "conversations_update" on public.conversations;
create policy "conversations_select" on public.conversations for select to authenticated
  using (auth.uid() in (user_a, user_b));
create policy "conversations_update" on public.conversations for update to authenticated
  using (auth.uid() in (user_a, user_b) and initiator_id <> auth.uid())
  with check (auth.uid() in (user_a, user_b) and initiator_id <> auth.uid());

drop policy if exists "messages_select" on public.messages;
drop policy if exists "messages_update_read" on public.messages;
create policy "messages_select" on public.messages for select to authenticated
  using (exists (
    select 1 from public.conversations c
    where c.id = messages.conversation_id and auth.uid() in (c.user_a, c.user_b)
  ));
create policy "messages_update_read" on public.messages for update to authenticated
  using (sender_id <> auth.uid() and exists (
    select 1 from public.conversations c
    where c.id = messages.conversation_id and auth.uid() in (c.user_a, c.user_b)
  ))
  with check (sender_id <> auth.uid() and exists (
    select 1 from public.conversations c
    where c.id = messages.conversation_id and auth.uid() in (c.user_a, c.user_b)
  ));

-- 권한: 필요한 것만 열어 둠 (메시지/대화방 생성은 아래 함수로만 가능)
revoke all on public.friendships, public.conversations, public.messages from anon, authenticated;
grant select, insert, delete on public.friendships to authenticated;
grant update (status) on public.friendships to authenticated;
grant select on public.conversations to authenticated;
grant update (status) on public.conversations to authenticated;
grant select on public.messages to authenticated;
grant update (read_at) on public.messages to authenticated;

-- ===== 4. 메시지 보내기 함수 =====
-- 친구면 바로 대화가 열리고, 친구가 아니면 '메시지 요청'으로 전달돼요.
-- 요청 단계에서는 메시지를 1개만 보낼 수 있어요.
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

-- ===== 5. 내 대화 목록 함수 (상대 이름, 마지막 메시지, 안 읽은 수) =====
create or replace function public.my_conversations()
returns table (
  conversation_id bigint,
  other_user_id uuid,
  other_name text,
  other_image text,
  status text,
  initiator_id uuid,
  last_body text,
  last_sender_id uuid,
  last_at timestamptz,
  unread_count int
)
language sql
stable
set search_path = public
as $$
  select
    c.id,
    case when c.user_a = auth.uid() then c.user_b else c.user_a end,
    coalesce(p.name, p.display_name, '알 수 없음'),
    p.image,
    c.status,
    c.initiator_id,
    lm.body,
    lm.sender_id,
    coalesce(lm.created_at, c.created_at),
    (select count(*) from public.messages m
      where m.conversation_id = c.id and m.sender_id <> auth.uid() and m.read_at is null)::int
  from public.conversations c
  left join public.portfolios p
    on p.user_id = case when c.user_a = auth.uid() then c.user_b else c.user_a end
  left join lateral (
    select m.body, m.sender_id, m.created_at
    from public.messages m
    where m.conversation_id = c.id
    order by m.id desc
    limit 1
  ) lm on true
  where auth.uid() in (c.user_a, c.user_b)
  order by coalesce(lm.created_at, c.created_at) desc;
$$;

revoke all on function public.send_message(uuid, text) from public, anon;
grant execute on function public.send_message(uuid, text) to authenticated;
revoke all on function public.my_conversations() from public, anon;
grant execute on function public.my_conversations() to authenticated;
