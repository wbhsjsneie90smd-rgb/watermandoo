-- comments 테이블에 "수정됨" 표시용 칸 추가
alter table public.comments add column if not exists updated_at timestamptz;
grant update (text, updated_at) on public.comments to authenticated;
