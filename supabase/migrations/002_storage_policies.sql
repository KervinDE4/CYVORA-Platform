create policy "Users upload own scan evidence"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'scan-evidence'
  and (storage.foldername(name))[1] = auth.uid()::text
);

create policy "Users view own scan evidence"
on storage.objects for select to authenticated
using (
  bucket_id = 'scan-evidence'
  and (storage.foldername(name))[1] = auth.uid()::text
);

create policy "Users delete own scan evidence"
on storage.objects for delete to authenticated
using (
  bucket_id = 'scan-evidence'
  and (storage.foldername(name))[1] = auth.uid()::text
);