CREATE TABLE "clawmuse_devices" (
	"server_id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"label" text NOT NULL,
	"offer" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "clawmuse_devices" ADD CONSTRAINT "clawmuse_devices_user_id_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."user"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "clawmuse_devices_user_idx" ON "clawmuse_devices" USING btree ("user_id");