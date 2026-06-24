import { createClient } from "jsr:@supabase/supabase-js@2";

const LEMON_SECRET = Deno.env.get("LEMON_WEBHOOK_SECRET") ?? "";

Deno.serve(async (req: Request): Promise<Response> => {
  try {
    const signature = req.headers.get("x-signature") ?? "";
    const body = await req.text();

    console.log("=== lemon-webhook ===");
    console.log("Signature length:", signature.length);
    console.log("Body length:", body.length);

    // --- Verifica firma HMAC ---
    if (LEMON_SECRET) {
      try {
        const key = await crypto.subtle.importKey(
          "raw",
          new TextEncoder().encode(LEMON_SECRET),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["verify"]
        );

        const hexMatch = signature.match(/.{2}/g);
        if (!hexMatch) {
          console.error("Signature non in formato hex valido:", signature);
          return new Response("Bad signature format", { status: 400 });
        }

        const sigBytes = new Uint8Array(hexMatch.map((b) => parseInt(b, 16)));
        const valid = await crypto.subtle.verify(
          "HMAC",
          key,
          sigBytes,
          new TextEncoder().encode(body)
        );

        if (!valid) {
          console.error("Firma HMAC non valida");
          return new Response("Unauthorized", { status: 401 });
        }
      } catch (sigErr) {
        console.error("Errore durante verifica firma:", sigErr);
        return new Response("Signature error", { status: 400 });
      }
    } else {
      console.warn("LEMON_WEBHOOK_SECRET non impostato — verifica firma SALTATA");
    }

    // --- Parse payload ---
    let payload: any;
    try {
      payload = JSON.parse(body);
    } catch (parseErr) {
      console.error("JSON parse fallito:", parseErr);
      return new Response("Bad JSON", { status: 400 });
    }

    const event = payload?.meta?.event_name ?? "";
    console.log("Event name:", event);

    const HANDLED_EVENTS = [
      "subscription_created",
      "subscription_updated",
      "subscription_resumed",
    ];

    if (!HANDLED_EVENTS.includes(event)) {
      console.log("Evento ignorato:", event);
      return new Response("Ignored", { status: 200 });
    }

    const attrs = payload?.data?.attributes ?? {};
    const email = attrs?.user_email ?? "";
    const status = attrs?.status ?? "";
    const endsAt = attrs?.ends_at ?? null;
    const isPro = status === "active" || status === "on_trial";

    console.log("Email:", email, "Status:", status, "isPro:", isPro);

    if (!email) {
      console.error("Payload senza email, payload:", JSON.stringify(payload));
      return new Response("No email", { status: 400 });
    }

    // --- Update Supabase ---
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    if (!supabaseUrl || !serviceKey) {
      console.error("Variabili ambiente Supabase mancanti");
      return new Response("Server misconfigured", { status: 500 });
    }

    const sb = createClient(supabaseUrl, serviceKey);

    const { error } = await sb
      .from("profiles")
      .update({
        is_pro: isPro,
        pro_expires_at: endsAt,
      })
      .eq("email", email);

    if (error) {
      console.error("Supabase update error:", error);
      // Ritorniamo 200 per evitare retry storm di Lemon su errori non recuperabili.
      return new Response("DB error logged", { status: 200 });
    }

    console.log(`[lemon-webhook] ${event} -> ${email} -> is_pro=${isPro}`);
    return new Response("OK", { status: 200 });

  } catch (fatalErr) {
    // Catch-all: qualsiasi errore non previsto non deve generare retry infiniti.
    console.error("ERRORE FATALE non gestito in lemon-webhook:", fatalErr);
    return new Response("Internal error logged", { status: 200 });
  }
});
