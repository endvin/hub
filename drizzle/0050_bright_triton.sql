CREATE TABLE "clawmuse_official_usage" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"service" text NOT NULL,
	"state" text NOT NULL,
	"seconds" integer DEFAULT 0 NOT NULL,
	"started_at" timestamp with time zone DEFAULT now() NOT NULL,
	"ended_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "clawmuse_official_usage" ADD CONSTRAINT "clawmuse_official_usage_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "clawmuse_official_usage_user_started" ON "clawmuse_official_usage" USING btree ("user_id","started_at");