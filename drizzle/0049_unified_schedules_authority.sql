CREATE TABLE "execution_authorities" (
	"execution_id" uuid PRIMARY KEY NOT NULL,
	"data" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "execution_credential_leases" (
	"id" uuid PRIMARY KEY NOT NULL,
	"execution_id" uuid NOT NULL,
	"data" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "trigger_schedules" (
	"trigger_id" uuid PRIMARY KEY NOT NULL,
	"recurrence" jsonb,
	"next_at" timestamp with time zone,
	"active_run_id" uuid
);
--> statement-breakpoint
ALTER TABLE "provider_event_receipts" DROP CONSTRAINT "provider_event_receipts_provider_check";--> statement-breakpoint
ALTER TABLE "execution_authorities" ADD CONSTRAINT "execution_authorities_execution_id_agent_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."agent_executions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "execution_credential_leases" ADD CONSTRAINT "execution_credential_leases_execution_id_agent_executions_id_fk" FOREIGN KEY ("execution_id") REFERENCES "public"."agent_executions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "trigger_schedules" ADD CONSTRAINT "trigger_schedules_trigger_id_organization_triggers_id_fk" FOREIGN KEY ("trigger_id") REFERENCES "public"."organization_triggers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "trigger_schedules" ADD CONSTRAINT "trigger_schedules_active_run_id_trigger_runs_id_fk" FOREIGN KEY ("active_run_id") REFERENCES "public"."trigger_runs"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "execution_credential_leases_execution_idx" ON "execution_credential_leases" USING btree ("execution_id");--> statement-breakpoint
CREATE INDEX "trigger_schedules_due_idx" ON "trigger_schedules" USING btree ("next_at");--> statement-breakpoint
ALTER TABLE "provider_event_receipts" ADD CONSTRAINT "provider_event_receipts_provider_check" CHECK ("provider_event_receipts"."provider" in ('github', 'slack', 'discord', 'linear', 'manual', 'schedule'));