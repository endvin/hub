import assert from "node:assert/strict";
import { describe, it } from "vitest";
import { composeEmailDelivery } from "../index.js";
import { createSmtpEmailDelivery, readSmtpConfig, type SendMail } from "./smtp.js";

const smtp = {
  SMTP_HOST: " smtp.email.ap-singapore-1.oci.oraclecloud.com ",
  SMTP_USER: "user",
  SMTP_PASSWORD: "secret",
  SMTP_FROM: "ClawMuse <noreply@example.com>",
};

describe("optional SMTP email delivery", () => {
  it("is absent without SMTP_HOST and requires credentials and a sender when enabled", () => {
    assert.equal(readSmtpConfig({}), undefined);
    assert.equal(readSmtpConfig({ SMTP_HOST: " " }), undefined);
    assert.throws(() => readSmtpConfig({ ...smtp, SMTP_FROM: "" }), /SMTP_FROM is required/);
    assert.throws(() => readSmtpConfig({ ...smtp, SMTP_PORT: "70000" }), /SMTP_PORT is invalid/);
    assert.deepEqual(readSmtpConfig(smtp), {
      host: "smtp.email.ap-singapore-1.oci.oraclecloud.com",
      port: 587,
      user: "user",
      password: "secret",
      from: "ClawMuse <noreply@example.com>",
    });
  });

  it("prefers Resend when both providers are configured", () => {
    assert.ok(composeEmailDelivery(smtp));
    assert.equal(composeEmailDelivery({}), undefined);
    assert.throws(
      () => composeEmailDelivery({ ...smtp, RESEND_API_KEY: "re_test_abc123" }),
      /RESEND_FROM is required/,
    );
  });

  it("sends the message from the configured sender", async () => {
    const sent: Parameters<SendMail>[0][] = [];
    const delivery = createSmtpEmailDelivery(readSmtpConfig(smtp)!, (mail) => {
      sent.push(mail);
      return Promise.resolve();
    });
    await delivery.send({
      to: "person@example.com",
      subject: "Verify",
      text: "text",
      html: "<p>html</p>",
      idempotencyKey: "verify:1",
    });
    assert.deepEqual(sent, [
      {
        from: "ClawMuse <noreply@example.com>",
        to: "person@example.com",
        subject: "Verify",
        text: "text",
        html: "<p>html</p>",
        headers: { "X-Entity-Ref-ID": "verify:1" },
      },
    ]);
  });
});
