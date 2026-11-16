-- =====================================================
-- 코멘트 수정 허용 (본인 코멘트만)
-- =====================================================
drop policy if exists "comments_update" on public.comments;
create policy "comments_update" on public.comments for update to authenticated
  using (auth.uid() = author_id) with check (auth.uid() = author_id);

grant update (text) on public.comments to authenticated;
