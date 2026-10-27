import { createResendEmailDelivery, readResendConfig } from "./internal/resend.js";
import { createSmtpEmailDelivery, readSmtpConfig } from "./internal/smtp.js";

export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
  idempotencyKey: string;
}

export interface EmailDelivery {
  send(message: EmailMessage): Promise<void>;
}

/** One production delivery boundary shared by every Hub email workflow. */
export function composeEmailDelivery(
  environment: Record<string, string | undefined> = process.env,
): EmailDelivery | undefined {
  const resend = readResendConfig(environment);
  if (resend !== undefined) return createResendEmailDelivery(resend);
  const smtp = readSmtpConfig(environment);
  return smtp === undefined ? undefined : createSmtpEmailDelivery(smtp);
}
