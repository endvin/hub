-- ClawMuse accounts registered while this instance had no email delivery were never asked to
-- verify. Email delivery now enforces verification, so treat the accounts that exist at this
-- upgrade as verified instead of locking them out.
UPDATE "user" SET "email_verified" = true, "updated_at" = now() WHERE "email_verified" = false;
