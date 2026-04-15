ALTER TABLE users ADD COLUMN onboarding_completed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE profiles ADD COLUMN onboarding_data_json TEXT NOT NULL DEFAULT '{}';
