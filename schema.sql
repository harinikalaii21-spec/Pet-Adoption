-- PawHome database schema (SQLite)
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  username   TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  role       TEXT NOT NULL CHECK (role IN ('user','org','admin')),
  email      TEXT NOT NULL DEFAULT '',
  phone      TEXT NOT NULL DEFAULT '',
  city       TEXT NOT NULL DEFAULT '',
  salt       TEXT NOT NULL,
  hash       TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pets (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  species        TEXT NOT NULL,
  breed          TEXT NOT NULL DEFAULT '',
  color          TEXT NOT NULL DEFAULT '',
  gender         TEXT NOT NULL DEFAULT 'Female',
  size           TEXT NOT NULL DEFAULT 'Medium',
  age_months     INTEGER NOT NULL DEFAULT 0,
  city           TEXT NOT NULL,
  status         TEXT NOT NULL DEFAULT 'available' CHECK (status IN ('available','reserved','adopted')),
  vaccinated     INTEGER NOT NULL DEFAULT 0,
  neutered       INTEGER NOT NULL DEFAULT 0,
  good_with_kids INTEGER NOT NULL DEFAULT 0,
  house_trained  INTEGER NOT NULL DEFAULT 0,
  description    TEXT NOT NULL DEFAULT '',
  owner_id       TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  owner_name     TEXT NOT NULL DEFAULT '',
  created_at     INTEGER NOT NULL,
  updated_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS photos (
  id       TEXT PRIMARY KEY,
  pet_id   TEXT NOT NULL REFERENCES pets(id) ON DELETE CASCADE,
  owner_id TEXT NOT NULL,
  data     TEXT NOT NULL,            -- image stored as a data: URL
  live     INTEGER NOT NULL DEFAULT 0,
  taken_at INTEGER,
  ord      INTEGER NOT NULL DEFAULT 0,
  at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS requests (
  id         TEXT PRIMARY KEY,
  pet_id     TEXT NOT NULL REFERENCES pets(id) ON DELETE CASCADE,
  pet_name   TEXT NOT NULL,
  owner_id   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  user_name  TEXT NOT NULL,
  user_email TEXT NOT NULL DEFAULT '',
  phone      TEXT NOT NULL,
  home       TEXT NOT NULL DEFAULT '',
  other_pets TEXT NOT NULL DEFAULT '',
  experience TEXT NOT NULL DEFAULT '',
  household  TEXT NOT NULL DEFAULT '',
  why        TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','review','approved','rejected','adopted')),
  note       TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pets_owner     ON pets(owner_id);
CREATE INDEX IF NOT EXISTS idx_photos_pet     ON photos(pet_id);
CREATE INDEX IF NOT EXISTS idx_requests_pet   ON requests(pet_id);
CREATE INDEX IF NOT EXISTS idx_requests_user  ON requests(user_id);
CREATE INDEX IF NOT EXISTS idx_requests_owner ON requests(owner_id);
