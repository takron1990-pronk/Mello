-- รันใน Supabase > SQL Editor ครั้งเดียว
create table if not exists public.mello_users (
  username text primary key check (char_length(username) between 1 and 254),
  display_name text not null,
  password_hash text not null,
  state jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
-- เปิด RLS และไม่สร้าง policy: เบราว์เซอร์ (anon key) เข้าตารางนี้ไม่ได้เลย
-- มีแต่ api/ ที่ใช้ service_role key เท่านั้นที่อ่าน/เขียนได้
alter table public.mello_users enable row level security;

-- ปิด auto-expose ไว้ จึงต้องให้สิทธิ์ service_role (ที่ api/ ใช้) เอง; anon/authenticated ไม่ได้สิทธิ์
grant all on public.mello_users to service_role;

-- ถ้าเคยรันฉบับเก่าไปแล้ว (จำกัด 40 ตัว) ให้รันสองบรรทัดนี้เพื่อรองรับอีเมล:
-- alter table public.mello_users drop constraint mello_users_username_check;
-- alter table public.mello_users add constraint mello_users_username_check check (char_length(username) between 1 and 254);
