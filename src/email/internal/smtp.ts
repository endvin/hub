import { createTransport } from "nodemailer";
import { z } from "zod";
import type { EmailDelivery, EmailMessage } from "../index.js";

const DELIVERY_TIMEOUT_MS = 10_000;

export interface SmtpConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  from: string;
}

export type SendMail = (mail: {
  from: string;
  to: string;
  subject: string;
  text: string;
  html: string;
  headers: Record<string, string>;
}) => Promise<unknown>;

const portSchema = z.coerce.number().int().min(1).max(65535);

/** SMTP with STARTTLS (port 587) or implicit TLS (465), e.g. OCI Email Delivery. */
export function readSmtpConfig(
  environment: Record<string, string | undefined>,
): SmtpConfig | undefined {
  const host = environment["SMTP_HOST"]?.trim();
  if (host === undefined || host.length === 0) return undefined;
  const required = (name: string): string => {
    const value = environment[name]?.trim();
    if (value === undefined || value.length === 0) {
      throw new Error(`${name} is required when SMTP_HOST is set`);
    }
    return value;
  };
  const port = portSchema.safeParse(environment["SMTP_PORT"]?.trim() || "587");
  if (!port.success) throw new Error("SMTP_PORT is invalid");
  return {
    host,
    port: port.data,
    user: required("SMTP_USER"),
    password: required("SMTP_PASSWORD"),
    from: required("SMTP_FROM"),
  };
}

export function createSmtpEmailDelivery(config: SmtpConfig, sendMail?: SendMail): EmailDelivery {
  const send =
    sendMail ??
    ((mail) =>
      createTransport({
        host: config.host,
        port: config.port,
        secure: config.port === 465,
        requireTLS: config.port !== 465,
        auth: { user: config.user, pass: config.password },
        connectionTimeout: DELIVERY_TIMEOUT_MS,
        greetingTimeout: DELIVERY_TIMEOUT_MS,
        socketTimeout: DELIVERY_TIMEOUT_MS,
      }).sendMail(mail));
  return {
    async send(message: EmailMessage) {
      await send({
        from: config.from,
        to: message.to,
        subject: message.subject,
        text: message.text,
        html: message.html,
        headers: { "X-Entity-Ref-ID": message.idempotencyKey },
      });
    },
  };
}
