/**
 * =============================================================================
 * PROJECT: TMG Secure Email Router & Backlog Cleanup (v6.0 - hardened)
 * PURPOSE: Triages Cesar's inbox with labels, prepares (but never sends) draft
 *          replies, and reviews historical clutter. Designed to FAIL SAFE:
 *          it never sends mail on its own and never deletes mail automatically.
 * DEPLOYMENT ACCOUNT: cesar@themarucagroup.com
 *
 * WHAT CHANGED FROM v5.0 (and why):
 *  - Removed the auto-send workflow. A draft is now sent only when YOU click
 *    Send in Gmail. A misplaced label can no longer dispatch a reply.
 *  - The automatic router NEVER trashes mail. Promotional mail is labelled and
 *    archived (still fully searchable, recoverable, and reversible).
 *  - Added scam detection. Money-demand + pressure language is flagged as
 *    _SuspectedScam and is NOT marked important, so scams are not elevated.
 *  - Trusted-sender allowlist protects booking platforms / known vendors from
 *    being mislabelled as promotional.
 *  - purgeOldClutter no longer sweeps category:updates (receipts, orders,
 *    confirmations) and still requires DRY_RUN=false to delete anything.
 * =============================================================================
 */

// ===== CONFIGURATION =====
const CONFIG = {
  BOSS_NAME: "Cesar",
  BOSS_EMAIL: Session.getEffectiveUser().getEmail().toLowerCase(),
  NOTIFY_EMAIL: "reservations@themarucagroup.com",
  CHECK_INTERVAL_MINUTES: 10,
  MAX_PROCESS_PER_RUN: 20,

  // SAFETY SWITCH. Leave true until you have reviewed several real summaries.
  // Even when false, this script never sends mail and never auto-trashes.
  DRY_RUN: true,

  // Gmail label workflow
  LABEL_PROCESSED: "_Processed",
  LABEL_URGENT: "_Urgent",
  LABEL_SUSPECTED_SCAM: "_SuspectedScam",
  LABEL_DRAFT_PENDING: "_DraftPending",
  LABEL_PROMOTIONAL: "_Promotional",
  LABEL_NEEDS_REVIEW: "_NeedsReview",

  // Historical backlog review limits
  PURGE_OLDER_THAN_DAYS: 30,
  PURGE_BATCH_LIMIT: 50
};

// Consumer email domains that can never be auto-classified as promotional.
const PERSONAL_DOMAINS = [
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
  "aol.com", "live.com", "msn.com", "protonmail.com", "mail.com", "zoho.com",
  "yahoo.se", "yahoo.fr", "yahoo.co.uk", "gmx.com", "ymail.com"
];

// Known business senders (booking platforms, vendors, partners). Mail from
// these domains is never labelled promotional and never archived/purged.
// Add the real domains you transact with.
const TRUSTED_DOMAINS = [
  "themarucagroup.com",
  "booking.com", "airbnb.com", "vrbo.com", "expedia.com", "hometogo.com",
  "stripe.com", "intuit.com", "quickbooks.com", "wellsfargo.com",
  "chase.com", "bankofamerica.com"
];

// Marketing / newsletter / cold-outreach language.
const PROMO_KEYWORDS = [
  "unsubscribe", "opt-out", "opt out", "newsletter", "promotion",
  "limited time", "act now", "buy now", "free trial", "advertisement",
  "sponsored", "no longer wish", "mailing list", "bulk mail", "mass email",
  "click here to", "special offer", "shop now", "need more leads",
  "manage your social", "raising capital", "are you the owner",
  "boost your bookings", "sell your business", "brand partnership",
  "we found you on instagram", "commercial cleaning", "jobs board",
  "creator deck", "loyalty offer", "merchant survey"
];

// Legal / financial / service-disruption warnings (genuine or not).
const URGENT_KEYWORDS = [
  "urgent", "critical", "emergency", "pre-legal", "legal action", "lawsuit",
  "court", "attorney", "irs", "license", "permit", "iata",
  "compliance", "lien", "judgment", "chargeback",
  "suspension", "suspended", "overdue", "outstanding balance",
  "insurance claim", "bank notice"
];

// Money-demand + pressure language. URGENT + these = likely scam.
const SCAM_KEYWORDS = [
  "wire transfer", "wire the", "send payment", "pay now to avoid",
  "payment immediately", "complete payment", "bitcoin", "crypto",
  "gift card", "western union", "moneygram", "avoid legal action",
  "account will be closed", "verify your account", "confirm your password",
  "gift cards", "purchase gift", "final notice", "you must pay"
];

// Guest / reservation inquiry language.
const CLIENT_KEYWORDS = [
  "refund", "complaint", "cancel", "receipt", "invoice", "damage", "broken",
  "not satisfied", "disappointed", "overcharge", "cleaning", "noise", "key",
  "lockbox", "wifi", "pool", "air condition", "hot water", "towel",
  "amenities", "early check", "late check", "extend stay", "modify booking",
  "compensation", "upgrade", "reservation", "check-in", "checkout",
  "my booking", "my stay", "villa", "confirmation", "new reservation",
  "booking confirmed", "reservation confirmed"
];

// ===== MAIN FUNCTIONS =====

/**
 * Triggered: scans the inbox and routes each new thread by label only.
 * Never sends mail. Never trashes mail.
 */
function processNewEmails() {
  Logger.log("=== TMG EMAIL ROUTER RUNNING (v6.0) ===");
  Logger.log("DRY_RUN Mode: " + CONFIG.DRY_RUN);

  try {
    ensureLabelsExist();
    const inboxThreads = GmailApp.getInboxThreads(0, CONFIG.MAX_PROCESS_PER_RUN);
    Logger.log("Retrieved " + inboxThreads.length + " threads from inbox.");

    let processedCount = 0;
    let promoArchivedCount = 0;
    let scamEmails = [];
    let urgentEmails = [];
    let clientDraftsCreated = [];

    for (const thread of inboxThreads) {
      if (hasLabel(thread, CONFIG.LABEL_PROCESSED)) continue;

      const messages = thread.getMessages();
      const latestMsg = messages[messages.length - 1];
      const from = latestMsg.getFrom();
      const subject = latestMsg.getSubject() || "";
      const body = latestMsg.getPlainBody() || "";
      const snippet = body.substring(0, 800);

      const emailData = {
        from: from,
        subject: subject,
        snippet: snippet,
        threadId: thread.getId()
      };

      Logger.log("Processing: \"" + subject + "\" | From: " + from);

      const text = subject + " " + snippet;
      const isUrgent = checkKeywords(text, URGENT_KEYWORDS);
      const isScam = checkKeywords(text, SCAM_KEYWORDS) && (isUrgent || isExternalAutomated(from));
      const isClient = checkKeywords(text, CLIENT_KEYWORDS);
      const isPromo = checkPromotional(subject, snippet, from);

      // Path A: Suspected scam. Flagged for caution, NOT marked important.
      if (isScam) {
        Logger.log("Classification: SUSPECTED SCAM (not elevated)");
        if (!CONFIG.DRY_RUN) {
          applyLabel(thread, CONFIG.LABEL_SUSPECTED_SCAM);
          markProcessed(thread);
        }
        scamEmails.push(emailData);
        processedCount++;
        continue;
      }

      // Path B: Genuine urgent / warning.
      if (isUrgent) {
        Logger.log("Classification: URGENT / WARNING");
        if (!CONFIG.DRY_RUN) {
          applyLabel(thread, CONFIG.LABEL_URGENT);
          thread.markImportant();
          markProcessed(thread);
        }
        urgentEmails.push(emailData);
        processedCount++;
        continue;
      }

      // Path C: Client / guest inquiry. A DRAFT is prepared. It is never sent
      // automatically -- review and send it yourself in Gmail.
      if (isClient) {
        Logger.log("Classification: CLIENT INQUIRY -> draft prepared (not sent)");
        const draftReplyText = generateProfessionalDraft(from, subject, snippet);
        if (!CONFIG.DRY_RUN) {
          thread.createDraftReply(draftReplyText);
          applyLabel(thread, CONFIG.LABEL_DRAFT_PENDING);
          markProcessed(thread);
        }
        clientDraftsCreated.push({ data: emailData, draftText: draftReplyText });
        processedCount++;
        continue;
      }

      // Path D: Promotional. Labelled and archived out of the inbox.
      // NOT trashed -- still searchable and reversible.
      if (isPromo) {
        Logger.log("Classification: PROMOTIONAL -> labelled + archived");
        if (!CONFIG.DRY_RUN) {
          applyLabel(thread, CONFIG.LABEL_PROMOTIONAL);
          markProcessed(thread);
          thread.moveToArchive();
        }
        promoArchivedCount++;
        processedCount++;
        continue;
      }

      // Path E: Unclassified. Flagged for human review, kept in inbox.
      Logger.log("Classification: UNKNOWN -> flagged for review");
      if (!CONFIG.DRY_RUN) {
        applyLabel(thread, CONFIG.LABEL_NEEDS_REVIEW);
        markProcessed(thread);
      }
      processedCount++;
    }

    if (scamEmails.length || urgentEmails.length || clientDraftsCreated.length || promoArchivedCount) {
      sendRouterNotificationSummary(scamEmails, urgentEmails, clientDraftsCreated, promoArchivedCount);
    }

    Logger.log("=== ROUTER CYCLE COMPLETE | Processed: " + processedCount + " ===");
  } catch (error) {
    handleScriptError("processNewEmails", error);
  }
}

/**
 * Manual review utility: lists historical clutter for inspection.
 * With DRY_RUN=true (default) it only reports. With DRY_RUN=false it archives
 * (does NOT trash) clutter so the action stays fully reversible.
 */
function reviewOldClutter() {
  Logger.log("=== HISTORICAL BACKLOG REVIEW RUNNING ===");
  Logger.log("DRY_RUN Safety Lock: " + CONFIG.DRY_RUN);

  try {
    // Narrowed: promotions/social only. category:updates is intentionally
    // excluded because it contains receipts, orders and confirmations.
    const searchQuery = "in:inbox older_than:" + CONFIG.PURGE_OLDER_THAN_DAYS +
      "d (category:promotions OR category:social OR unsubscribe)";
    Logger.log("Search Query: " + searchQuery);

    const threads = GmailApp.search(searchQuery, 0, CONFIG.PURGE_BATCH_LIMIT);
    Logger.log("Found " + threads.length + " candidate threads.");

    let scannedCount = 0;
    let archivedCount = 0;
    let bypassedClientCount = 0;
    let bypassedTrustedCount = 0;

    for (const thread of threads) {
      scannedCount++;
      const subject = thread.getFirstMessageSubject() || "";
      const messages = thread.getMessages();
      if (messages.length === 0) continue;

      const lastMsg = messages[messages.length - 1];
      const from = lastMsg.getFrom();
      const snippet = (lastMsg.getPlainBody() || "").substring(0, 500);
      const text = subject + " " + snippet;

      if (checkKeywords(text, CLIENT_KEYWORDS) ||
          checkKeywords(text, URGENT_KEYWORDS) ||
          checkKeywords(text, SCAM_KEYWORDS)) {
        Logger.log("[BYPASS] client/urgent terms: \"" + subject + "\"");
        bypassedClientCount++;
        continue;
      }

      if (checkPersonalDomainWhitelist(from) || isTrustedSender(from)) {
        Logger.log("[BYPASS] trusted/personal sender: " + from);
        bypassedTrustedCount++;
        continue;
      }

      Logger.log("[CLUTTER] " + subject + " | From: " + from);
      if (!CONFIG.DRY_RUN) {
        thread.moveToArchive();
      }
      archivedCount++;
    }

    Logger.log("=== REVIEW COMPLETE ===");
    Logger.log("Scanned: " + scannedCount + " | Archived: " + archivedCount +
      " | Bypassed client/urgent: " + bypassedClientCount +
      " | Bypassed trusted: " + bypassedTrustedCount);

    GmailApp.sendEmail(
      CONFIG.NOTIFY_EMAIL,
      "Historical Inbox Review Report (DRY_RUN: " + CONFIG.DRY_RUN + ")",
      "Backlog review completed.\n\n" +
      "- Scanned threads: " + scannedCount + "\n" +
      "- Clutter archived: " + archivedCount + "\n" +
      "- Safeguarded client/urgent threads: " + bypassedClientCount + "\n" +
      "- Safeguarded trusted/personal senders: " + bypassedTrustedCount + "\n\n" +
      "Note: this routine archives clutter, it never deletes it. Archived mail " +
      "is still searchable and can be moved back to the inbox at any time."
    );
  } catch (error) {
    handleScriptError("reviewOldClutter", error);
  }
}

// ===== HELPER FUNCTIONS =====

function checkKeywords(text, keywordList) {
  if (!text) return false;
  const lowerText = text.toLowerCase();
  for (const keyword of keywordList) {
    if (lowerText.indexOf(keyword.toLowerCase()) !== -1) return true;
  }
  return false;
}

function extractDomain(fromHeader) {
  const m = (fromHeader || "").toLowerCase().match(/@([a-z0-9._-]+)/);
  return m ? m[1] : "";
}

function isTrustedSender(fromHeader) {
  const domain = extractDomain(fromHeader);
  for (const trusted of TRUSTED_DOMAINS) {
    if (domain === trusted || domain.endsWith("." + trusted)) return true;
  }
  return false;
}

function checkPersonalDomainWhitelist(fromHeader) {
  return PERSONAL_DOMAINS.indexOf(extractDomain(fromHeader)) !== -1;
}

/** True if the sender looks like an unattended/external automated mailbox. */
function isExternalAutomated(fromHeader) {
  if (isTrustedSender(fromHeader)) return false;
  const fromLower = (fromHeader || "").toLowerCase();
  const prefixes = ["noreply@", "no-reply@", "newsletter@", "marketing@",
    "promo@", "offers@", "deals@", "alerts@"];
  for (const p of prefixes) {
    if (fromLower.indexOf(p) !== -1) return true;
  }
  return false;
}

/**
 * Conservative promotional classifier. Trusted senders are never promotional.
 */
function checkPromotional(subject, snippet, from) {
  if (isTrustedSender(from)) return false;

  const combined = (subject + " " + snippet).toLowerCase();
  const isPersonalDomain = checkPersonalDomainWhitelist(from);

  let promoScore = 0;
  for (const term of PROMO_KEYWORDS) {
    if (combined.indexOf(term.toLowerCase()) !== -1) promoScore++;
  }

  const automated = isExternalAutomated(from);

  // A personal-domain sender is only promotional with strong, explicit signal.
  if (isPersonalDomain) {
    return promoScore >= 3 && automated;
  }
  // Otherwise require either clear keyword evidence, or an automated address
  // that also shows at least one promo signal (automated alone is not enough).
  return promoScore >= 2 || (automated && promoScore >= 1);
}

function getSenderName(fromHeader) {
  const match = (fromHeader || "").match(/^"?([^"<]+)"?\s*</);
  if (match) return match[1].trim();
  return (fromHeader || "").split("@")[0];
}

/**
 * Builds a polite draft reply. The draft only acknowledges receipt and
 * promises follow-up -- it never commits to a refund, credit, or outcome.
 */
function generateProfessionalDraft(fromHeader, subject, bodySnippet) {
  const clientName = getSenderName(fromHeader);
  const text = (subject + " " + bodySnippet).toLowerCase();

  const greeting = "Dear " + clientName + ",\n\n";
  const closing = "\n\nBest regards,\n" + CONFIG.BOSS_NAME + "\nThe Maruca Group";
  let body;

  if (text.indexOf("refund") !== -1) {
    body = "Thank you for reaching out regarding your refund request. " +
      "I have received your message and our team will review the details of " +
      "your booking. I will follow up with you personally once that review " +
      "is complete.";
  } else if (text.indexOf("cancel") !== -1) {
    body = "Thank you for letting us know about the cancellation of your " +
      "reservation. Our reservations team will review your booking and the " +
      "applicable policy, and I will follow up with the next steps shortly.";
  } else if (text.indexOf("charge") !== -1 || text.indexOf("invoice") !== -1) {
    body = "Thank you for contacting us about the charge on your account. " +
      "I will review the invoice and payment history for your booking and " +
      "follow up with you so we can resolve any questions together.";
  } else {
    body = "Thank you for your message regarding your reservation. I have " +
      "received your inquiry and will coordinate with our reservations team " +
      "to get back to you with a full response shortly.";
  }

  return greeting + body + closing +
    "\n\n[DRAFT prepared automatically -- review and edit before sending.]";
}

function hasLabel(thread, labelName) {
  const labels = thread.getLabels();
  for (const label of labels) {
    if (label.getName() === labelName) return true;
  }
  return false;
}

function applyLabel(thread, labelName) {
  const label = GmailApp.getUserLabelByName(labelName);
  if (label) thread.addLabel(label);
}

function markProcessed(thread) {
  applyLabel(thread, CONFIG.LABEL_PROCESSED);
}

function ensureLabelsExist() {
  const requiredLabels = [
    CONFIG.LABEL_PROCESSED,
    CONFIG.LABEL_URGENT,
    CONFIG.LABEL_SUSPECTED_SCAM,
    CONFIG.LABEL_DRAFT_PENDING,
    CONFIG.LABEL_PROMOTIONAL,
    CONFIG.LABEL_NEEDS_REVIEW
  ];
  for (const name of requiredLabels) {
    if (!GmailApp.getUserLabelByName(name)) {
      GmailApp.createLabel(name);
      Logger.log("Created label: " + name);
    }
  }
}

function sendRouterNotificationSummary(scamList, urgentList, clientDraftList, promoArchivedCount) {
  let subject = "TMG Email Manager Summary Report";
  let body = "=== TMG EMAIL ROUTER SUMMARY ===\n";
  body += "Time: " + new Date().toLocaleString() + "\n";
  body += "DRY RUN MODE: " + CONFIG.DRY_RUN + "\n\n";

  if (promoArchivedCount > 0) {
    body += "Promotional mail labelled + archived: " + promoArchivedCount +
      " threads (still searchable, not deleted)\n\n";
  }

  if (scamList.length > 0) {
    subject = "ATTENTION: " + scamList.length + " suspected scam email(s) flagged";
    body += "SUSPECTED SCAM EMAILS (" + scamList.length + "):\n";
    body += "Do NOT pay, wire funds, or click links in these. Verify independently.\n";
    body += "-------------------------------------------------\n";
    for (const email of scamList) {
      body += "From: " + email.from + "\n";
      body += "Subject: " + email.subject + "\n";
      body += "Snippet: " + email.snippet.substring(0, 150) + "...\n\n";
    }
  }

  if (urgentList.length > 0) {
    body += "\nURGENT / WARNING EMAILS (" + urgentList.length + "):\n";
    body += "-------------------------------------------------\n";
    for (const email of urgentList) {
      body += "From: " + email.from + "\n";
      body += "Subject: " + email.subject + "\n";
      body += "Snippet: " + email.snippet.substring(0, 150) + "...\n\n";
    }
  }

  if (clientDraftList.length > 0) {
    body += "\nCLIENT REPLIES -- DRAFTS PREPARED (" + clientDraftList.length + "):\n";
    body += "Review each draft in Gmail and click Send yourself. " +
      "Nothing is sent automatically.\n";
    body += "-------------------------------------------------\n";
    for (const draft of clientDraftList) {
      body += "From: " + draft.data.from + "\n";
      body += "Subject: " + draft.data.subject + "\n";
      body += "Draft preview: \"" + draft.draftText.substring(0, 120) + "...\"\n\n";
    }
  }

  body += "-------------------------------------------------\n";
  body += "Automated notification from the TMG Email Manager script.";

  try {
    GmailApp.sendEmail(CONFIG.NOTIFY_EMAIL, subject, body);
    Logger.log("Summary report emailed.");
  } catch (error) {
    Logger.log("[WARN] Notification email failed: " + error.message);
  }
}

// ===== DIAGNOSTICS & TRIGGERS =====

/** Evaluates mock inputs against the classifier without touching Gmail. */
function testEmailClassification() {
  Logger.log("=== EMAIL CLASSIFICATION TEST ===");

  const testCases = [
    { from: "marketing@digipeak.net", subject: "Increase bookings, gain more high-quality leads today!", snippet: "Hi owner, our agency specializes in social media strategy. Unsubscribe here." },
    { from: "johndoe@gmail.com", subject: "Refund Request", snippet: "Hi Cesar, I stayed in your villa and there was no hot water. I would like a refund for my booking." },
    { from: "pre-legalescalation@booking-support-billing.com", subject: "WARNING: Avoid listing suspension", snippet: "Outstanding invoice past overdue. Complete wire transfer immediately to avoid legal action." },
    { from: "guest@icloud.com", subject: "Question regarding pool keys", snippet: "Hello, we are checking in tomorrow and wanted to know where the lockbox for the key is." },
    { from: "newsletter@facebookmail.com", subject: "Notification: Social media updates", snippet: "You have 5 new notifications. Unsubscribe here." },
    { from: "noreply@booking.com", subject: "Reservation confirmed", snippet: "A new reservation has been confirmed for your villa." },
    { from: "irs-gov-notice@irs.gov", subject: "IRS Audit Notice - Tax Permit Compliance Required", snippet: "Notice of compliance deficiency regarding state tax and permits." }
  ];

  for (let i = 0; i < testCases.length; i++) {
    const tc = testCases[i];
    const text = tc.subject + " " + tc.snippet;
    const isUrgent = checkKeywords(text, URGENT_KEYWORDS);
    const isScam = checkKeywords(text, SCAM_KEYWORDS) && (isUrgent || isExternalAutomated(tc.from));
    const isClient = checkKeywords(text, CLIENT_KEYWORDS);
    const isPromo = checkPromotional(tc.subject, tc.snippet, tc.from);

    let classification = "UNKNOWN / REVIEW";
    if (isScam) classification = "SUSPECTED SCAM";
    else if (isUrgent) classification = "URGENT / WARNING";
    else if (isClient) classification = "CLIENT DRAFT REPLY";
    else if (isPromo) classification = "PROMOTIONAL (archive)";

    Logger.log("[TEST " + (i + 1) + "] " + tc.subject + " | " + tc.from);
    Logger.log("         ===> " + classification);
  }

  Logger.log("=== TEST COMPLETED ===");
}

/** Installs the inbox-scan trigger. There is no auto-send trigger by design. */
function installAutomatedTriggers() {
  removeTriggers();
  ScriptApp.newTrigger("processNewEmails")
    .timeBased()
    .everyMinutes(CONFIG.CHECK_INTERVAL_MINUTES)
    .create();
  Logger.log("Trigger installed: processNewEmails every " +
    CONFIG.CHECK_INTERVAL_MINUTES + " minutes. No auto-send trigger exists.");
}

function removeTriggers() {
  const triggers = ScriptApp.getProjectTriggers();
  for (const trigger of triggers) {
    ScriptApp.deleteTrigger(trigger);
  }
  Logger.log("All time triggers deleted.");
}

// ===== ERROR HANDLING =====

function handleScriptError(functionName, error) {
  const errMsg = "Error in '" + functionName + "': " + error.toString();
  Logger.log("[ERROR] " + errMsg);
  try {
    GmailApp.sendEmail(
      CONFIG.NOTIFY_EMAIL,
      "TMG Email Manager Script Error",
      "The script failed while running " + functionName + ".\n\n" +
      error.toString() + "\n\nTime: " + new Date().toLocaleString()
    );
  } catch (notificationError) {
    Logger.log("[FATAL] Could not send error notification: " + notificationError.message);
  }
}
