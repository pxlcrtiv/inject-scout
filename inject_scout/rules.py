"""Detection rule catalog — deterministic, regex/string based, no I/O.

Each rule: id, category, severity, one or more regex patterns, explanation,
suggestion. Matching is case-insensitive and whitespace-normalized so
multi-line and oddly-spaced attacks still hit.

Severity convention:
  error  — high-confidence, high-impact (leaks, exfiltration, full takeover)
  warn   — strong signal, common in real attacks (role escape, jailbreak)
  info   — suspicious / worth reviewing (indirect-injection hints)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES = (
    "role-escape",
    "system-prompt-leak",
    "delimiter-confusion",
    "exfiltration",
    "encoded-attack",
    "indirect-injection",
    "tool-abuse",
    "jailbreak",
)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    patterns: tuple[str, ...]
    explanation: str
    suggestion: str


# Pattern language: every string is a regex, applied case-insensitively on a
# whitespace-normalized copy of the input (so newlines/extra spaces don't
# defeat matching).
RULES: tuple[Rule, ...] = (
    # ---- role escape -------------------------------------------------------
    Rule(
        "ROLE_ESCAPE_IGNORE", "role-escape", "warn",
        (
            r"ignore (all |any )?(previous|prior|above|earlier|given) (instructions|prompts?|messages?|context|rules)",
            r"disregard (all |any )?(previous|prior|above|earlier) (instructions|prompts?|messages?|rules)",
            r"don'?t (follow|obey|listen to) (the )?(previous|system|initial) (instructions|prompt)",
        ),
        "The prompt tries to discard its original instructions (a classic top-of-prompt injection).",
        "Treat the text as untrusted: keep the system instructions fixed; if this is user input, never splice it into the system prompt.",
    ),
    Rule(
        "ROLE_ESCAPE_NEW_ROLE", "role-escape", "warn",
        (
            r"you are now (dan|ai|assistant|a bot) (with|without) (no |any )(rules|limits|restrictions)",
            r"act as (dan|an? (unrestricted|unfiltered|jailbroken) (ai|model|assistant))",
            r"pretend you are (dan|a model with no (rules|safety))",
            r"switch to (dan mode|developer mode|unfiltered mode|jailbreak mode)",
        ),
        "The prompt demands a persona identity shift that typically removes safety constraints.",
        "Refuse persona overrides in production contexts; validate the user's role before honoring mode switches.",
    ),
    Rule(
        "ROLE_ESCAPE_FORGET", "role-escape", "warn",
        (
            r"forget (everything|all (your |the )?(previous|prior|instructions|rules|training))",
            r"erase (your|the) (memory|instructions|persona)",
            r"clear (your|the) (context|instructions|memory)",
        ),
        "Attempts to wipe the model's prior context so injected instructions take over.",
        "Context-clearing requests are a red flag in chatbots with memory; log and gate them.",
    ),
    Rule(
        "ROLE_CONFUSION", "role-escape", "warn",
        (
            r"ignore (the fact|that)( that)? (you are|you'?re) (an ai|a bot|an assistant|a model)",
            r"stop (being|acting like) (an ai|a bot|an assistant|a language model)",
            r"forget (that )?(you are|you'?re) (an ai|a bot|an assistant|a model)",
        ),
        "Tries to make the model abandon its helper identity (the setup step of many role-theft chains).",
        "Keep identity fixed in the system prompt; flag identity-abandonment phrasings.",
    ),
    # ---- system prompt leak -------------------------------------------------
    Rule(
        "LEAK_SYSTEM_PROMPT", "system-prompt-leak", "error",
        (
            r"(reveal|repeat|show|print|output|share|display|dump|copy|paste) (your|the|its) (system prompt|system instructions|initial prompt|base prompt|instructions verbatim)",
            r"what( is|'?s| are) (your|the) (system prompt|system instructions|initial prompt|hidden prompt)",
            r"output (the )?(system prompt|all instructions) (verbatim|exactly|word for word)",
            r"tell me (everything|all) (in|from) (your|the) (system prompt|instructions|prompt)",
        ),
        "Directly asks the model to expose its system prompt — the most common leak attempt.",
        "Never include secrets or rules you wouldn't publish in the system prompt; treat leak asks as an incident signal.",
    ),
    Rule(
        "LEAK_PROMPT_START", "system-prompt-leak", "error",
        (
            r"(print|show|repeat) (the )?(text|words|message) (that |which )?(comes|appears|is) (at|before) (the |this )?(start|beginning|first) (of|line|sentence|paragraph)",
            r"what (is|'?s|are) (the |your )?(first|very first|initial) (instruction|message|prompt|line|sentence|rule)",
            r"what (comes|is) (at|before|at the top of) (the |this )?(prompt|message|instructions)",
        ),
        "Asks for the beginning of the prompt — a leak variant that dodges 'system prompt' wording.",
        "Same handling as LEAK_SYSTEM_PROMPT; audit anything these prompts precede.",
    ),
    Rule(
        "LEAK_RULES", "system-prompt-leak", "error",
        (
            r"what (are|is|'?re) (your|the|all your) (rules|guidelines|constraints|guardrails|instructions list)",
            r"(list|enumerate|tell me) (all|every one of) (your|the) (rules|guidelines|constraints)",
        ),
        "Asks for the full rule set the model operates under.",
        "Treat like LEAK_SYSTEM_PROMPT; ensure the rule set contains nothing sensitive.",
    ),
    # ---- delimiter confusion ------------------------------------------------
    Rule(
        "DELIMITER_IGNORE", "delimiter-confusion", "warn",
        (
            r"ignore (the )?(system|message|text|previous|prior) (delimiter|boundary|separator|marker)s?",
            r"((disregard|ignore) )?(everything|all the text) (before|above|preceding) (this|the) (line|message|marker)",
            r"from (this|the) (point|line|message) (on|forward),? (ignore|forget) (the |anything )?(before|above|earlier)",
        ),
        "Tries to invalidate the trusted/rest-data boundary the app relies on.",
        "Enforce structural boundaries in code (separate fields), not by prompting; flag inputs that reference delimiters.",
    ),
    Rule(
        "DELIMITER_SPLIT", "delimiter-confusion", "info",
        (
            r"(divide|split|separate) (the |your |our )?(response|answer|output|reply) into (two|multiple|separate|different)( (separate|different|distinct))? (messages|parts|sections|answers)",
            r"answer (twice|two (ways|times)|in two parts)",
        ),
        "Asks for split/forked answers — a common pattern for smuggling a second, unguarded response.",
        "Treat multi-part answers as two outputs; scan each part independently.",
    ),
    # ---- exfiltration ---------------------------------------------------------
    Rule(
        "EXFIL_NETWORK", "exfiltration", "error",
        (
            r"(send|post|upload|forward|email|exfiltrat\w*) (this|the|all|these) (data|information|results|conversation|content|text) (to|via|through) (http|https|webhook|api|email|url)",
            r"(fetch|load|download|open|visit) (this|the|a|an) (url|link|website|page):? https?://",
            r"(print|output|return|encode) .{0,40} (as|in|to) (base64|url-encoded|hex) (so I can|to (send|exfiltrat|post|upload))",
        ),
        "Asks the model to move data to an external destination or transform it for transport.",
        "If your app has tool access to the network, scope it to an allowlist; never let prompt content select the destination.",
    ),
    Rule(
        "EXFIL_FORMAT", "exfiltration", "info",
        (
            r"(output|return|print|show) (only|exactly|just) (the )?(json|base64|hex|url-encoded) (of|for|version of) (the|this|all)",
            r"respond (with|in) (only )?(base64|json|hex)",
        ),
        "Oblivious exfil often asks for a transport-friendly encoding of *everything*.",
        "Require explicit scoping: 'output only the field X' should still pass validation of intent.",
    ),
    Rule(
        "EXFIL_CREDENTIALS", "exfiltration", "error",
        (
            r"(api[- ]?key|password|secret|token|credential|private key|pwd).{0,40}(send|post|output|print|reveal|return|display)",
            r"(send|post|output|print|reveal|return|display).{0,40}(api[- ]?key|password|secret|token|credential|private key|pwd)",
        ),
        "Credential-specific extraction request — high-confidence exfiltration attempt.",
        "Block by default; alert on the actor. No legitimate workflow needs the model to exfiltrate credentials.",
    ),
    # ---- encoded / obfuscated attacks ---------------------------------------
    Rule(
        "ENCODED_LEET", "encoded-attack", "warn",
        (
            r"1gnore.{0,30}(1nstruct|pr0mpt)",
            r"(j41lbr34k|br34k|h4ck|p4ssw0rd|0v3rride|1nject|3nc0de)",
            r"1nstruct10ns|pr0mpt5",
        ),
        "Leetspeak / digit-substitution obfuscation of attack keywords.",
        "Normalize common leetspeak before passing input to models (and note it in logs).",
    ),
    Rule(
        "ENCODED_REVERSED", "encoded-attack", "info",
        (
            r"(reverse|read backwards|decode) (this|the) (text|message|prompt|instructions)",
            r"(base64|rot13|hex|binary) (decoded|decode) (instructions|prompt|message)",
        ),
        "Requests to decode hidden payloads — often the carrier for secondary injections.",
        "Block decoded-carrier flows in untrusted input channels.",
    ),
    # ---- indirect injection ----------------------------------------------------
    Rule(
        "INDIRECT_FOLLOW", "indirect-injection", "info",
        (
            r"follow (the )?(instructions|directions|commands) (in|found in|embedded in|contained in|hidden in) (the|this|that) (url|website|web ?page|document|file|image|html|email|post)",
            r"from now on (follow|obey) (the )?(instructions|text|content) (in|on) (the|that|this)",
            r"ignore previous instructions and (follow|do what it says in) (the|this) (url|page|document|image)",
        ),
        "Hallmark of indirect prompt injection (malicious instructions inside fetched content).",
        "Sandbox fetched content; tell the model what is data vs instructions, and strip control phrases.",
    ),
    Rule(
        "INDIRECT_EMBED", "indirect-injection", "warn",
        (
            r"<\|?(system|user|assistant|instruction|prompt)\|?>",
            r"\[(system|instruction|prompt)\]:",
            r"(start|begin) (new |another )?(message|conversation|turn|session)",
        ),
        "Injected tag-like or turn-switching markers meant to masquerade as framework messages.",
        "Sanitize angle-bracket/list markers in display text; treat embedded tags as content, never as commands.",
    ),
    # ---- tool abuse --------------------------------------------------------------
    Rule(
        "TOOL_EXECUTE", "tool-abuse", "warn",
        (
            r"(call|run|execute|invoke|trigger|use) (the |your )?(tools?|functions?|actions?|plugins?) (to|with|that)",
            r"use (your|the) (search|browser|calculator|shell|terminal|database|sql|python|code) (tool|function) (to|with|on)",
            r"access (the )?(internet|web|browser|database|filesystem|shell)",
        ),
        "Prompts the model to drive a tool in a broad/unspecified way — often a precursor to abuse.",
        "Give tools least-privilege scopes and require explicit, narrow parameters from trusted flows.",
    ),
    Rule(
        "TOOL_HTTP", "tool-abuse", "info",
        (
            r"(fetch|get|download|open|read|visit) (the )?(content|page|data) (at|from|of) (this|the|a) (url|link|endpoint|api)",
            r"https?://[^\s]{5,}",
        ),
        "URL references inside a prompt (benign in many apps, but a vector when tools can fetch).",
        "Only resolve URLs against an allowlist and with user-visible confirmation.",
    ),
    # ---- jailbreak ----------------------------------------------------------------
    Rule(
        "JAILBREAK_DAN", "jailbreak", "error",
        (
            r"\bdan (mode|style|prompt|protocol)\b",
            r"do anything now",
            r"developer mode",
            r"unrestricted (mode|ai|assistant)",
            r"no (rules|restrictions|limitations|filter|safety (protocols?|guidelines)) (apply|whatsoever|at all|for you)",
            r"uncensored (mode|ai|model)",
        ),
        "Known jailbreak idioms asking the model to disable its safeguards.",
        "Deny at the policy layer; log user + attempt for abuse review.",
    ),
    Rule(
        "JAILBREAK_SIMULATE", "jailbreak", "warn",
        (
            r"simulate (being|having|a) (an? )?(ai|model|assistant) (with|without|that has) no (rules|safety|restrictions|limits)",
            r"pretend (you|your model) (has|have) no (safety|rules|restrictions)",
            r"role[- ]?play as a (malicious|evil|unfiltered|amoral|no-?limit) (assistant|ai|bot)",
            r"write (this|a response) as if (you|the model) (had|has) no (safety|guidelines)",
        ),
        "Role-play framing used to launder harmful requests past safety training.",
        "Treat simulated-unrestricted requests as normal policy violations, not harmless games.",
    ),
    Rule(
        "JAILBREAK_CANNOT", "jailbreak", "warn",
        (
            r"never (say|admit|mention|state|tell) (that )?(you|your model|it) (can'?t|cannot|is unable|won'?t|will not|are not able)",
            r"don'?t (say|admit|mention) (you|it) (can'?t|cannot|are not able)",
            r"always (say yes|answer positively|respond affirmatively) no matter what",
        ),
        "Meta-constraint evasion: removing the model's ability to refuse.",
        "Refusal is a feature; prompts that forbid it should be blocked at the policy layer.",
    ),
    Rule(
        "JAILBREAK_SPLIT", "jailbreak", "info",
        (
            r"(ignore|skip) (my|the) (next|following) (sentence|paragraph|message|instruction)",
            r"(say|repeat|start) (yes|ok|done|understood) (then|and) (ignore|forget) (my|the) (next|last) (instruction)",
            r"[a-z0-9]{8,}[-_ ][a-z0-9]{8,}[-_ ][a-z0-9]{8,}",  # token-splitting artifacts
        ),
        "Fragmentation tricks that split harmful instructions across chunks.",
        "Join and re-scan chunked input before evaluation for deterministic apps.",
    ),
)


def cacheable_pattern(rule: Rule) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{p})" for p in rule.patterns), re.IGNORECASE)


def normalize(text: str) -> str:
    """Whitespace-normalized copy for matching (keeps original spans via offsets
    computed on the normalized string — close enough for reporting)."""
    return re.sub(r"\s+", " ", text).strip()


WHITESPACE_OFFSET = None  # spans are reported on the normalized text