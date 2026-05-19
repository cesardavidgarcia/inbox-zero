/**
 * =============================================================================
 * PROJECT: TMG Secure Email Router & Backlog Cleanup (v7.0)
 * PURPOSE: Triages Cesar's inbox with labels, auto-trashes junk/promotional
 *          mail, detects cold outreach and auto-trashes it after a grace
 *          period, and prepares (but never sends) draft replies to guests.
 * DEPLOYMENT ACCOUNT: cesar@themarucagroup.com
 *
 * BEHAVIOUR SUMMARY:
 *  - Junk / promotional mail        -> trashed immediately (automatic).
 *  - Cold outreach (unknown sender) -> labelled _ColdEmail, then trashed
 *                                      automatically after COLD_EMAIL_TRASH_
 *                                      AFTER_DAYS (default 10) days.
 *  - Suspected scam                 -> labelled _SuspectedScam (kept, not
 *                                      elevated).
 *  - Urgent / warning               -> labelled _Urgent, marked important.
 *  - Guest / client inquiry         -> draft reply prepared (NEVER auto-sent).
 *  - Unclassified                   -> labelled _NeedsReview, kept in inbox.
 *
 * SAFETY NOTES:
 *  - Client / urgent / scam mail and trusted senders are NEVER trashed.
 *  - Cold mail sits under the _ColdEmail label for the grace period so you
 *    can rescue anything mislabelled before it is trashed.
 *  - Gmail keeps trashed mail recoverable for 30 days regardless.
 *  - Draft replies are never sent automatically -- you review and send them.
 * =============================================================================
 */

// ===== CONFIGURATION =====
const CONFIG = {
  BOSS_NAME: "Cesar",
  BOSS_EMAIL: Session.getEffectiveUser().getEmail().toLowerCase(),
  NOTIFY_EMAIL: "reservations@themarucagroup.com",
  CHECK_INTERVAL_MINUTES: 10,
  MAX_PROCESS_PER_RUN: 20,

  // SAFETY SWITCH. While true, the script does NOT modify any mail: it never
  // trashes, archives, labels, or drafts. It still writes its execution log
  // and still emails the summary/report so you can review what it WOULD do.
  // Set to false to let it act for real.
  DRY_RUN: true,

  // Gmail label workflow
  LABEL_PROCESSED: "_Processed",
  LABEL_URGENT: "_Urgent",
  LABEL_SUSPECTED_SCAM: "_SuspectedScam",
  LABEL_DRAFT_PENDING: "_DraftPending",
  LABEL_COLD_EMAIL: "_ColdEmail",
  LABEL_NEEDS_REVIEW: "_NeedsReview",

  // Cold-email grace period: flagged cold mail is auto-trashed after this many
  // days. Until then it lives under the _ColdEmail label so you can rescue it.
  COLD_EMAIL_TRASH_AFTER_DAYS: 10,

  // Historical backlog review limits
  PURGE_OLDER_THAN_DAYS: 30,
  PURGE_BATCH_LIMIT: 50
};

// Script-property keys tracking multi-page backlog-review progress so a large
// cleanup can resume across several short, quota-safe runs.
const CLUTTER_PROP_OFFSET = "CLUTTER_REVIEW_OFFSET";
const CLUTTER_PROP_SCANNED = "CLUTTER_REVIEW_SCANNED";
const CLUTTER_PROP_TRASHED = "CLUTTER_REVIEW_TRASHED";
const CLUTTER_PROP_BYPASSED = "CLUTTER_REVIEW_BYPASSED";

// Script-property key holding a {threadId: flaggedAtMillis} map so the cold-
// email grace period is measured from when a thread was flagged, not from
// when its message was received.
const COLD_PROP_FLAG_DATES = "COLD_EMAIL_FLAG_DATES";

// Consumer email domains that can never be auto-classified as promotional.
const PERSONAL_DOMAINS = [
  "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "icloud.com",
  "aol.com", "live.com", "msn.com", "protonmail.com", "mail.com", "zoho.com",
  "yahoo.se", "yahoo.fr", "yahoo.co.uk", "gmx.com", "ymail.com"
];

// Known business senders (booking platforms, vendors, partners). Mail from
// these domains is never trashed, labelled promotional, or flagged cold.
// EDIT THIS to match the real domains TMG actually transacts with.
const TRUSTED_DOMAINS = [
  "themarucagroup.com",
  "booking.com", "airbnb.com", "vrbo.com", "expedia.com", "hometogo.com",
  "stripe.com", "intuit.com", "quickbooks.com", "wellsfargo.com",
  "chase.com", "bankofamerica.com"
];

// Marketing / newsletter language.
const PROMO_KEYWORDS = [
  "unsubscribe", "opt-out", "opt out", "newsletter", "promotion",
  "limited time", "act now", "buy now", "free trial", "advertisement",
  "sponsored", "no longer wish", "mailing list", "bulk mail", "mass email",
  "click here to", "special offer", "shop now", "discount", "coupon",
  "sale ends", "loyalty offer", "merchant survey", "creator deck"
];

// Cold-outreach phrasing (unsolicited sales / partnership pitches).
const COLD_EMAIL_KEYWORDS = [
  "quick question", "saw your website", "came across your",
  "found your website", "found you on instagram", "i help businesses",
  "we help businesses", "i help companies", "we help companies",
  "boost your revenue", "boost your bookings", "would love to connect",
  "hop on a call", "15-minute call", "15 minute call", "schedule a call",
  "book a call", "are you the owner", "generate more leads",
  "need more leads", "grow your business", "i noticed your",
  "partnership opportunity", "brand partnership", "wanted to reach out",
  "i'm reaching out", "i am reaching out", "reaching out because",
  "following up on my last", "circling back", "circle back",
  "we specialize in", "drive more traffic", "manage your social",
  "raising capital", "sell your business", "commercial cleaning"
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
  "gift card", "gift cards", "purchase gift", "western union", "moneygram",
  "avoid legal action", "account will be closed", "verify your account",
  "confirm your password", "final notice", "you must pay"
];

// Guest / reservation inquiry language.
const CLIENT_KEYWORDS = [
  "refund", "complaint", "cancel", "cancellation", "cancelled", "canceled",
  "receipt", "invoice", "damage", "broken",
  "not satisfied", "disappointed", "overcharge", "cleaning", "noise", "key",
  "lockbox", "wifi", "pool", "air condition", "air conditioning", "hot water",
  "towel", "amenities", "early check", "late check", "extend stay",
  "extended stay", "modify booking",
  "compensation", "upgrade", "reservation", "check-in", "checkout",
  "my booking", "my stay", "villa", "confirmation", "new reservation",
  "booking confirmed", "reservation confirmed"
];

// ===== MAIN FUNCTIONS =====

/**
 * Triggered: scans the inbox and routes each new thread.
 * Trashes junk/promotional mail automatically. Flags cold mail.
 * Never sends mail automatically.
 */
function processNewEmails() {
  Logger.log("=== TMG EMAIL ROUTER RUNNING (v7.0) ===");
  Logger.log("DRY_RUN Mode: " + CONFIG.DRY_RUN);

  try {
    ensureLabelsExist();
    const inboxThreads = GmailApp.getInboxThreads(0, CONFIG.MAX_PROCESS_PER_RUN);
    Logger.log("Retrieved " + inboxThreads.length + " threads from inbox.");

    let processedCount = 0;
    let promoTrashedCount = 0;
    let coldFlaggedCount = 0;
    let scamEmails = [];
    let urgentEmails = [];
    let clientDraftsCreated = [];
    const coldFlagMap = getColdFlagMap();

    for (const thread of inboxThreads) {
      if (hasLabel(thread, CONFIG.LABEL_PROCESSED)) continue;

      const messages = thread.getMessages();
      if (messages.length === 0) continue;
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
      // Automated mailboxes (incl. trusted-platform notifications such as
      // "Reservation confirmed" from noreply@booking.com) are excluded from
      // client classification so they never receive a spurious draft reply.
      const isClient = checkKeywords(text, CLIENT_KEYWORDS) &&
        !isAutomatedAddress(from);
      const isPromo = checkPromotional(subject, snippet, from);
      // Path C may call isColdEmail(..., true) for client-vs-cold ambiguity;
      // Path D calls isColdEmail() without that flag. hasPriorRelationship()
      // (GmailApp.search) runs only after cheaper isColdEmail checks pass.

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

      // Path C: Client / guest inquiry. A DRAFT is prepared, never sent.
      if (isClient) {
        // A genuine guest inquiry can share vocabulary with a cold sales
        // pitch ("villa", "cleaning", "reservation"). If the email ALSO
        // carries cold-outreach signals it is ambiguous -- route it to
        // _NeedsReview for a human decision rather than drafting a reply
        // (could be a pitch) or auto-archiving it (could be a real guest).
        if (isColdEmail(from, subject, snippet, true)) {
          Logger.log("Classification: AMBIGUOUS (client + cold) -> _NeedsReview");
          if (!CONFIG.DRY_RUN) {
            applyLabel(thread, CONFIG.LABEL_NEEDS_REVIEW);
            markProcessed(thread);
          }
          processedCount++;
          continue;
        }
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

      // Path D: Cold outreach from an unknown sender. Flagged + archived now;
      // auto-trashed later by purgeFlaggedColdEmails after the grace period.
      if (isColdEmail(from, subject, snippet)) {
        Logger.log("Classification: COLD OUTREACH -> flagged _ColdEmail (trash in " +
          CONFIG.COLD_EMAIL_TRASH_AFTER_DAYS + "d)");
        if (!CONFIG.DRY_RUN) {
          applyLabel(thread, CONFIG.LABEL_COLD_EMAIL);
          markProcessed(thread);
          thread.moveToArchive();
          coldFlagMap[thread.getId()] = Date.now();
        }
        coldFlaggedCount++;
        processedCount++;
        continue;
      }

      // Path E: Junk / promotional. Trashed immediately (automatic).
      // Marked _Processed first so that, if you recover a false positive
      // from Trash back to the inbox, it is not re-classified and re-trashed.
      if (isPromo) {
        Logger.log("Classification: JUNK / PROMOTIONAL -> trashed");
        if (!CONFIG.DRY_RUN) {
          markProcessed(thread);
          thread.moveToTrash();
        }
        promoTrashedCount++;
        processedCount++;
        continue;
      }

      // Path F: Unclassified. Flagged for human review, kept in inbox.
      Logger.log("Classification: UNKNOWN -> flagged for review");
      if (!CONFIG.DRY_RUN) {
        applyLabel(thread, CONFIG.LABEL_NEEDS_REVIEW);
        markProcessed(thread);
      }
      processedCount++;
    }

    if (!CONFIG.DRY_RUN) saveColdFlagMap(coldFlagMap);

    if (scamEmails.length || urgentEmails.length || clientDraftsCreated.length ||
        promoTrashedCount || coldFlaggedCount) {
      sendRouterNotificationSummary(scamEmails, urgentEmails, clientDraftsCreated,
        promoTrashedCount, coldFlaggedCount);
    }

    Logger.log("=== ROUTER CYCLE COMPLETE | Processed: " + processedCount + " ===");
  } catch (error) {
    handleScriptError("processNewEmails", error);
  }
}

/**
 * Triggered (daily): trashes cold-flagged mail once it is past the grace
 * period. A thread is rescued (and unflagged) if you replied to it or moved
 * it back to the inbox in the meantime.
 */
function purgeFlaggedColdEmails() {
  Logger.log("=== COLD-EMAIL AUTO-PURGE RUNNING ===");
  Logger.log("DRY_RUN Mode: " + CONFIG.DRY_RUN);

  try {
    const coldLabel = GmailApp.getUserLabelByName(CONFIG.LABEL_COLD_EMAIL);
    if (!coldLabel) {
      Logger.log("No _ColdEmail label found; nothing to purge.");
      return;
    }

    const threads = coldLabel.getThreads();
    const cutoffMs = CONFIG.COLD_EMAIL_TRASH_AFTER_DAYS * 24 * 60 * 60 * 1000;
    const now = Date.now();
    const flagMap = getColdFlagMap();
    const nextFlagMap = {};

    let trashedCount = 0;
    let rescuedCount = 0;
    let waitingCount = 0;

    for (const thread of threads) {
      const threadId = thread.getId();

      // Rescue: the owner engaged with it (replied) or moved it back to inbox.
      if (threadHasReplyFromBoss(thread) || thread.isInInbox()) {
        Logger.log("[RESCUE] engaged thread, unflagging: " +
          thread.getFirstMessageSubject());
        if (!CONFIG.DRY_RUN) thread.removeLabel(coldLabel);
        rescuedCount++;
        continue;
      }

      // Grace period is measured from when the thread was flagged _ColdEmail,
      // not from when its message was received -- so a thread that was
      // already old when flagged (e.g. backlog at first deployment) still
      // gets a full rescue window. A thread with no recorded flag date (map
      // lost, or flagged before this tracking existed) starts its clock now.
      const flaggedAt = flagMap[threadId] || now;
      if (now - flaggedAt < cutoffMs) {
        waitingCount++;
        nextFlagMap[threadId] = flaggedAt;
        continue;
      }

      Logger.log("[TRASH COLD] " + thread.getFirstMessageSubject());
      if (!CONFIG.DRY_RUN) {
        thread.removeLabel(coldLabel);
        thread.moveToTrash();
      }
      trashedCount++;
    }

    if (!CONFIG.DRY_RUN) saveColdFlagMap(nextFlagMap);

    Logger.log("=== COLD-EMAIL PURGE COMPLETE ===");
    Logger.log("Trashed: " + trashedCount + " | Rescued: " + rescuedCount +
      " | Still within grace period: " + waitingCount);

    if (trashedCount > 0 || rescuedCount > 0) {
      GmailApp.sendEmail(
        CONFIG.NOTIFY_EMAIL,
        "Cold-Email Auto-Purge Report (DRY_RUN: " + CONFIG.DRY_RUN + ")",
        "Cold-email auto-purge completed.\n\n" +
        "- Cold emails trashed (past " + CONFIG.COLD_EMAIL_TRASH_AFTER_DAYS +
        "-day grace period): " + trashedCount + "\n" +
        "- Rescued (you replied or moved back to inbox): " + rescuedCount + "\n" +
        "- Still within grace period: " + waitingCount + "\n\n" +
        "Trashed mail remains recoverable from Gmail Trash for 30 days."
      );
    }
  } catch (error) {
    handleScriptError("purgeFlaggedColdEmails", error);
  }
}

/**
 * Manual review utility for historical clutter. With DRY_RUN=true it only
 * reports; with DRY_RUN=false it trashes promotional/social backlog.
 *
 * Large backlogs are handled automatically: when a run fills an entire page
 * (PURGE_BATCH_LIMIT threads) it schedules a one-shot trigger to continue
 * ~2 minutes later, walking the whole backlog without hitting Apps Script
 * execution limits. Progress and running totals are kept in script
 * properties; one summary email is sent when the final page is reached.
 */
function reviewOldClutter() {
  Logger.log("=== HISTORICAL BACKLOG REVIEW RUNNING ===");
  Logger.log("DRY_RUN Mode: " + CONFIG.DRY_RUN);

  try {
    removeClutterContinuationTriggers();
    const props = PropertiesService.getScriptProperties();
    const offset = parseInt(props.getProperty(CLUTTER_PROP_OFFSET) || "0", 10);

    // Narrowed: promotions/social only. category:updates is intentionally
    // excluded because it contains receipts, orders and confirmations.
    const searchQuery = "in:inbox older_than:" + CONFIG.PURGE_OLDER_THAN_DAYS +
      "d (category:promotions OR category:social OR unsubscribe)";
    Logger.log("Search: " + searchQuery + " | offset: " + offset);

    const threads = GmailApp.search(searchQuery, offset, CONFIG.PURGE_BATCH_LIMIT);
    Logger.log("Found " + threads.length + " candidate threads on this page.");

    let scannedCount = 0;
    let trashedCount = 0;
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

      Logger.log("[TRASH CLUTTER] " + subject + " | From: " + from);
      if (!CONFIG.DRY_RUN) {
        thread.moveToTrash();
      }
      trashedCount++;
    }

    const bypassedCount = bypassedClientCount + bypassedTrustedCount;
    const totalScanned = addToProperty(props, CLUTTER_PROP_SCANNED, scannedCount);
    const totalTrashed = addToProperty(props, CLUTTER_PROP_TRASHED, trashedCount);
    const totalBypassed = addToProperty(props, CLUTTER_PROP_BYPASSED, bypassedCount);

    Logger.log("Page done. Scanned: " + scannedCount + " | Trashed: " +
      trashedCount + " | Bypassed: " + bypassedCount);

    if (threads.length === CONFIG.PURGE_BATCH_LIMIT) {
      // Trashed threads drop out of the search next run; bypassed ones do not,
      // so the offset must skip past them. In DRY_RUN nothing is removed, so
      // skip every thread scanned on this page instead.
      const advanceBy = CONFIG.DRY_RUN ? scannedCount : bypassedCount;
      props.setProperty(CLUTTER_PROP_OFFSET, String(offset + advanceBy));
      setClutterContinuationTrigger();
      Logger.log("Full page reached -- continuation scheduled in ~2 minutes.");
      return;
    }

    // Final page reached: report grand totals and clear stored progress.
    props.deleteProperty(CLUTTER_PROP_OFFSET);
    props.deleteProperty(CLUTTER_PROP_SCANNED);
    props.deleteProperty(CLUTTER_PROP_TRASHED);
    props.deleteProperty(CLUTTER_PROP_BYPASSED);

    Logger.log("=== REVIEW COMPLETE (all pages) ===");
    GmailApp.sendEmail(
      CONFIG.NOTIFY_EMAIL,
      "Historical Inbox Cleanup Report (DRY_RUN: " + CONFIG.DRY_RUN + ")",
      "Backlog cleanup completed across all pages.\n\n" +
      "- Total threads scanned: " + totalScanned + "\n" +
      "- Total clutter trashed: " + totalTrashed + "\n" +
      "- Total safeguarded (client/urgent/trusted/personal): " + totalBypassed + "\n\n" +
      "Trashed mail remains recoverable from Gmail Trash for 30 days."
    );
  } catch (error) {
    handleScriptError("reviewOldClutter", error);
  }
}

/** Wrapper invoked by the one-shot backlog-review continuation trigger. */
function reviewOldClutterMore() {
  reviewOldClutter();
}

/** Schedules reviewOldClutter to continue ~2 minutes from now. */
function setClutterContinuationTrigger() {
  ScriptApp.newTrigger("reviewOldClutterMore")
    .timeBased()
    .at(new Date(Date.now() + 1000 * 60 * 2))
    .create();
}

/** Removes any pending backlog-review continuation triggers. */
function removeClutterContinuationTriggers() {
  const triggers = ScriptApp.getProjectTriggers();
  for (const trigger of triggers) {
    if (trigger.getHandlerFunction() === "reviewOldClutterMore") {
      ScriptApp.deleteTrigger(trigger);
    }
  }
}

/** Adds delta to an integer script property and returns the new total. */
function addToProperty(props, key, delta) {
  const next = parseInt(props.getProperty(key) || "0", 10) + delta;
  props.setProperty(key, String(next));
  return next;
}

/** Reads the {threadId: flaggedAtMillis} cold-email tracking map. */
function getColdFlagMap() {
  const raw = PropertiesService.getScriptProperties().getProperty(COLD_PROP_FLAG_DATES);
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch (e) {
    Logger.log("[WARN] cold-flag map unreadable, resetting: " + e.message);
    return {};
  }
}

/** Persists the {threadId: flaggedAtMillis} cold-email tracking map. */
function saveColdFlagMap(map) {
  PropertiesService.getScriptProperties()
    .setProperty(COLD_PROP_FLAG_DATES, JSON.stringify(map));
}

// ===== HELPER FUNCTIONS =====

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Whole-word / whole-phrase keyword match. Uses word boundaries so short
 * keywords (e.g. "irs", "court", "lien") do not match inside unrelated words
 * such as "first", "courtyard", or "client".
 */
function checkKeywords(text, keywordList) {
  if (!text) return false;
  const lowerText = text.toLowerCase();
  for (const keyword of keywordList) {
    const pattern = new RegExp("\\b" + escapeRegex(keyword.toLowerCase()) + "\\b");
    if (pattern.test(lowerText)) return true;
  }
  return false;
}

function extractDomain(fromHeader) {
  const m = (fromHeader || "").toLowerCase().match(/@([a-z0-9._-]+)/);
  return m ? m[1] : "";
}

function extractEmail(fromHeader) {
  const m = (fromHeader || "").match(/<([^>]+)>/);
  if (m) return m[1].toLowerCase().trim();
  const bare = (fromHeader || "").match(/[a-z0-9._%+-]+@[a-z0-9._-]+/i);
  return bare ? bare[0].toLowerCase() : "";
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

/** True if the address looks like an unattended automated mailbox. */
function isAutomatedAddress(fromHeader) {
  const fromLower = (fromHeader || "").toLowerCase();
  const prefixes = ["noreply@", "no-reply@", "donotreply@", "newsletter@",
    "marketing@", "promo@", "offers@", "deals@", "alerts@",
    "notifications@", "notification@", "mailer@"];
  for (const p of prefixes) {
    if (fromLower.indexOf(p) !== -1) return true;
  }
  return false;
}

/** True if the sender is an external (non-trusted) automated mailbox. */
function isExternalAutomated(fromHeader) {
  if (isTrustedSender(fromHeader)) return false;
  return isAutomatedAddress(fromHeader);
}

/**
 * True if we have any prior outbound correspondence with this sender, i.e.
 * the account has previously sent mail to that address. Used to tell genuine
 * contacts apart from cold (first-contact) senders.
 */
function hasPriorRelationship(fromHeader) {
  const email = extractEmail(fromHeader);
  if (!email) return false;
  if (email === CONFIG.BOSS_EMAIL) return true;
  try {
    return GmailApp.search('in:sent to:' + email, 0, 1).length > 0;
  } catch (e) {
    Logger.log("[WARN] prior-relationship lookup failed: " + e.message);
    return false;
  }
}

/**
 * Detects unsolicited cold outreach: cold-pitch phrasing from an external
 * sender we have never emailed before. Trusted and personal-domain senders
 * are exempt, as is anyone we already correspond with.
 *
 * When ignorePersonalDomainWhitelist is true, the personal-domain exemption
 * is skipped so Path C can still treat client-looking mail from Gmail etc.
 * as ambiguous when it also matches cold-pitch keywords (Path D unchanged).
 */
function isColdEmail(fromHeader, subject, snippet, ignorePersonalDomainWhitelist) {
  if (isTrustedSender(fromHeader)) return false;
  if (!ignorePersonalDomainWhitelist && checkPersonalDomainWhitelist(fromHeader)) {
    return false;
  }
  if (!checkKeywords(subject + " " + snippet, COLD_EMAIL_KEYWORDS)) return false;
  return !hasPriorRelationship(fromHeader);
}

/** Conservative promotional classifier. Trusted senders are never promotional. */
function checkPromotional(subject, snippet, from) {
  if (isTrustedSender(from)) return false;

  const combined = (subject + " " + snippet).toLowerCase();
  const isPersonalDomain = checkPersonalDomainWhitelist(from);

  let promoScore = 0;
  for (const term of PROMO_KEYWORDS) {
    const pattern = new RegExp("\\b" + escapeRegex(term.toLowerCase()) + "\\b");
    if (pattern.test(combined)) promoScore++;
  }

  const automated = isExternalAutomated(from);

  if (isPersonalDomain) {
    return promoScore >= 3 && automated;
  }
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

/** True if the account owner has sent at least one message in this thread. */
function threadHasReplyFromBoss(thread) {
  const messages = thread.getMessages();
  for (const msg of messages) {
    if (extractEmail(msg.getFrom()) === CONFIG.BOSS_EMAIL) return true;
  }
  return false;
}

function ensureLabelsExist() {
  const requiredLabels = [
    CONFIG.LABEL_PROCESSED,
    CONFIG.LABEL_URGENT,
    CONFIG.LABEL_SUSPECTED_SCAM,
    CONFIG.LABEL_DRAFT_PENDING,
    CONFIG.LABEL_COLD_EMAIL,
    CONFIG.LABEL_NEEDS_REVIEW
  ];
  for (const name of requiredLabels) {
    if (!GmailApp.getUserLabelByName(name)) {
      GmailApp.createLabel(name);
      Logger.log("Created label: " + name);
    }
  }
}

function sendRouterNotificationSummary(scamList, urgentList, clientDraftList,
                                       promoTrashedCount, coldFlaggedCount) {
  let subject = "TMG Email Manager Summary Report";
  let body = "=== TMG EMAIL ROUTER SUMMARY ===\n";
  body += "Time: " + new Date().toLocaleString() + "\n";
  body += "DRY RUN MODE: " + CONFIG.DRY_RUN + "\n\n";

  if (promoTrashedCount > 0) {
    body += "Junk / promotional mail trashed automatically: " +
      promoTrashedCount + " threads\n";
  }
  if (coldFlaggedCount > 0) {
    body += "Cold outreach flagged (_ColdEmail, auto-trash in " +
      CONFIG.COLD_EMAIL_TRASH_AFTER_DAYS + " days): " + coldFlaggedCount +
      " threads\n";
  }
  if (promoTrashedCount > 0 || coldFlaggedCount > 0) body += "\n";

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

  // Keep the DRY_RUN status in the subject, consistent with the other
  // report emails, so a dry-run scam alert is not mistaken for a live one.
  subject += " (DRY_RUN: " + CONFIG.DRY_RUN + ")";

  try {
    GmailApp.sendEmail(CONFIG.NOTIFY_EMAIL, subject, body);
    Logger.log("Summary report emailed.");
  } catch (error) {
    Logger.log("[WARN] Notification email failed: " + error.message);
  }
}

// ===== DIAGNOSTICS & TRIGGERS =====

/**
 * Evaluates mock inputs against the classifier and logs each result.
 * Note: the cold-outreach check calls hasPriorRelationship(), which runs one
 * GmailApp.search() over Sent mail -- so the cold-email verdict for a test
 * case reflects the live account's actual correspondence history.
 */
function testEmailClassification() {
  Logger.log("=== EMAIL CLASSIFICATION TEST ===");

  const testCases = [
    { from: "marketing@digipeak.net", subject: "Increase bookings, gain leads today!", snippet: "Hi owner, our agency specializes in social media. Unsubscribe here. Special offer." },
    { from: "johndoe@gmail.com", subject: "Refund Request", snippet: "Hi Cesar, I stayed in your villa and there was no hot water. I would like a refund." },
    { from: "pre-legal@booking-support-billing.com", subject: "WARNING: Avoid listing suspension", snippet: "Outstanding invoice past overdue. Complete wire transfer immediately to avoid legal action." },
    { from: "guest@icloud.com", subject: "Question regarding pool keys", snippet: "Hello, we are checking in tomorrow and wanted to know where the lockbox for the key is." },
    { from: "alex@growthagency.io", subject: "Quick question for The Maruca Group", snippet: "Hi, I came across your website and wanted to reach out. We help businesses generate more leads. Can we hop on a call?" },
    { from: "noreply@booking.com", subject: "Reservation confirmed", snippet: "A new reservation has been confirmed for your villa." },
    { from: "irs-gov-notice@irs.gov", subject: "IRS Audit Notice - Tax Permit Compliance Required", snippet: "Notice of compliance deficiency regarding state tax and permits." }
  ];

  for (let i = 0; i < testCases.length; i++) {
    const tc = testCases[i];
    const text = tc.subject + " " + tc.snippet;
    const isUrgent = checkKeywords(text, URGENT_KEYWORDS);
    const isScam = checkKeywords(text, SCAM_KEYWORDS) && (isUrgent || isExternalAutomated(tc.from));
    const isClient = checkKeywords(text, CLIENT_KEYWORDS) &&
      !isAutomatedAddress(tc.from);
    const isPromo = checkPromotional(tc.subject, tc.snippet, tc.from);
    const isCold = isColdEmail(tc.from, tc.subject, tc.snippet);
    const isColdAmbiguous = isColdEmail(tc.from, tc.subject, tc.snippet, true);

    let classification = "UNKNOWN / REVIEW";
    if (isScam) classification = "SUSPECTED SCAM";
    else if (isUrgent) classification = "URGENT / WARNING";
    else if (isClient) classification = isColdAmbiguous
      ? "AMBIGUOUS (client + cold) -> _NeedsReview"
      : "CLIENT DRAFT REPLY";
    else if (isCold) classification = "COLD OUTREACH (flag + auto-trash)";
    else if (isPromo) classification = "JUNK / PROMOTIONAL (trash now)";

    Logger.log("[TEST " + (i + 1) + "] " + tc.subject + " | " + tc.from);
    Logger.log("         ===> " + classification);
  }

  Logger.log("=== TEST COMPLETED ===");
}

/**
 * Installs the time triggers:
 *  - processNewEmails       : every CHECK_INTERVAL_MINUTES
 *  - purgeFlaggedColdEmails : once per day
 * There is intentionally no auto-send trigger.
 */
function installAutomatedTriggers() {
  removeTriggers();

  ScriptApp.newTrigger("processNewEmails")
    .timeBased()
    .everyMinutes(CONFIG.CHECK_INTERVAL_MINUTES)
    .create();

  ScriptApp.newTrigger("purgeFlaggedColdEmails")
    .timeBased()
    .everyDays(1)
    .create();

  Logger.log("Triggers installed: processNewEmails every " +
    CONFIG.CHECK_INTERVAL_MINUTES + " minutes; purgeFlaggedColdEmails daily.");
}

function removeTriggers() {
  const triggers = ScriptApp.getProjectTriggers();
  const managedHandlers = ["processNewEmails", "purgeFlaggedColdEmails"];
  for (const trigger of triggers) {
    if (managedHandlers.indexOf(trigger.getHandlerFunction()) !== -1) {
      ScriptApp.deleteTrigger(trigger);
    }
  }
  Logger.log("Managed router triggers deleted (processNewEmails, purgeFlaggedColdEmails).");
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
