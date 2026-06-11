"""Regex-based AI threat detection with categorized patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


SAFE_CONTEXT_PATTERNS: list[str] = [
    r"\bhow does .{3,60} work\b",
    r"\bwhat is (a |an |the )?.{3,60}\b",
    r"\bexplain .{3,60}\b",
    r"\btell me about .{3,60}\b",
    r"\bhistory of .{3,60}\b",
    r"\bfor my (class|course|homework|project|study|learning)\b",
    r"\bin (python|javascript|java|ruby|c\+\+|sql|html|css)\b",
    r"\bmy own (computer|laptop|phone|device|account|server)\b",
    r"\b(how to|how do i) (protect|secure|prevent|defend|avoid|recognize)\b",
    r"\b(legally|legitimately|ethically|authorized|my own|for educational)\b",
    r"\bfor (educational|academic|learning|research|study) purposes?\b",
    r"\bcd [/~\w\-\.]+\b",
    r"\bls [/~\w\-\.]*\b",
    r"\bgit (clone|pull|push|commit|status|log|diff|branch)\b",
    r"\b(pip|npm|yarn|brew|apt|conda) (install|uninstall|update)\b",
    r"\b(python|node|ruby|java|php|go|rust)\b.*\.(py|js|rb|java|php|go|rs)\b",
    r"\buvicorn|fastapi|streamlit|django|flask|react|vue|angular\b",
]

_COMPILED_SAFE_CONTEXT_PATTERNS = [
    re.compile(pattern, re.IGNORECASE) for pattern in SAFE_CONTEXT_PATTERNS
]

HIGH_SEVERITY_CATEGORIES = frozenset({"harmful_content", "malicious_code", "radicalization"})


@dataclass(frozen=True)
class RegexDetectionResult:
    matched: bool
    matched_patterns: list[str]
    matched_categories: list[str]
    highest_category_score: int
    category_details: dict[str, dict[str, Any]]
    safe_context_count: int


DETECTION_CATEGORIES: dict[str, dict[str, Any]] = {
    "prompt_injection": {
        "base_score": 40,
        "patterns": [
            r"ignore (all |previous |your )?(instructions?|rules?|guidelines?|directives?|commands?)",
            r"disregard (all |previous |your )?(instructions?|rules?|guidelines?|training)",
            r"forget (all |your |previous )?(instructions?|rules?|training|guidelines?|context)",
            r"override (your )?(instructions?|settings?|configuration|programming|rules?)",
            r"(new|different|updated|revised) (instructions?|rules?|directives?|guidelines?|prompt)",
            r"(your |the )?(real|true|actual|original) (instructions?|purpose|goal|objective|mission)",
            r"(bypass|circumvent|skip|avoid) (your )?(instructions?|rules?|guidelines?|training|filters?)",
            r"from now on (you (are|will|must|should)|ignore|forget|disregard)",
            r"you (are|will) no longer (follow|obey|adhere to|abide by)",
            r"(stop|cease|end) (following|obeying|adhering to) (your )?(rules?|instructions?|guidelines?)",
            r"(your|the) (previous|prior|old|last) (instructions?|prompt|context|conversation) (is|are) (void|invalid|cancelled|deleted|gone|wiped)",
            r"(replace|swap|substitute|change) (your )?(instructions?|rules?|system prompt|guidelines?)",
            r"(act|behave|respond|operate) (as if|like) (you have no|without any|ignoring) (rules?|restrictions?|guidelines?|instructions?)",
            r"(pretend|imagine|suppose|assume) (your )?(instructions?|rules?|guidelines?) (do not|don't|didn't) exist",
            r"(null|void|delete|erase|remove|clear) (your )?(instructions?|rules?|prompt|context|memory)",
            r"system\s*:\s*(ignore|new|updated|override|forget)",
            r"<\s*system\s*>",
            r"\[system\]",
            r"###\s*(instruction|system|override|prompt)",
            r"---(new|updated|system|override)---",
            r"print your (system )?prompt",
            r"(show|reveal|display|output|repeat|tell me) (your |the )?(system |hidden |original |base |real )?(prompt|instructions?|rules?|guidelines?|directives?)",
            r"what (were|are) you (told|instructed|programmed|trained) (to do|to say|to avoid)",
            r"reveal (your )?(initialization|base|original|starting|system) (prompt|instructions?|context)",
            r"(output|print|show|display|list|repeat) (all |your )?(instructions?|rules?|configuration|directives?|guidelines?)",
        ],
    },
    "jailbreak": {
        "base_score": 45,
        "patterns": [
            r"\bDAN\b",
            r"do anything now",
            r"jailbreak",
            r"(no|without|remove|strip|disable|turn off) (restrictions?|limitations?|constraints?|filters?|guardrails?|safety|censorship)",
            r"(unrestricted|unfiltered|uncensored|unlimited|free|liberated|unchained) (ai|assistant|mode|version|claude|gpt|llm|model)",
            r"(pretend|act|behave|respond) (as if you|like you|as though you) (have no|don't have|without) (restrictions?|rules?|guidelines?|filters?|limits?)",
            r"(you are|you're|become|act as) (a |an )?(free|unrestricted|unfiltered|uncensored|evil|rogue|rebel|unchained|liberated|unaligned) (ai|assistant|bot|version|entity|model)",
            r"(enable|activate|turn on|switch to|enter) (developer|jailbreak|god|admin|unrestricted|freedom|chaos|evil|dark|hacker|root) mode",
            r"(your|the) (true|real|inner|actual|hidden|secret) (self|nature|purpose|form|identity|persona) (has no|without|is free from) (restrictions?|rules?|limits?|filters?)",
            r"(break|escape|remove|disable|unlock) (free from |out of )?(your )?(chains?|cage|prison|restrictions?|shackles?|constraints?|limits?)",
            r"(opposite|reverse|inverse|anti|contrary) (of )?(your )?(rules?|guidelines?|restrictions?|training|programming)",
            r"everything (is|becomes) (allowed|permitted|legal|okay|fine|acceptable) (now|in this mode)",
            r"(there are|no|without) (no )?(rules?|laws?|restrictions?|limits?|guidelines?) (here|anymore|now|in this (context|scenario|world|game))",
            r"(respond|answer|reply) (without|ignoring|bypassing|disregarding) (any |your )?(filters?|restrictions?|safety|guidelines?|training|rules?)",
            r"hypothetically (speaking )?(with no restrictions?|if you had no rules?|as a free ai|without any limits?)",
            r"(for (fictional|creative|educational|research|academic|story|hypothetical) purposes?,? )(ignore|bypass|disregard|forget) (your )?(rules?|restrictions?|guidelines?|filters?)",
            r"(roleplay|rp|play) (as |the role of )?(an |a )?(ai|assistant|bot|entity) (with no|without|that has no) (rules?|restrictions?|guidelines?|filters?|limits?)",
            r"(you are|you're|imagine you are) (not|no longer) (bound by|restricted by|limited by|subject to|constrained by) (any |your )?(rules?|guidelines?|restrictions?|training|filters?)",
            r"(grandma|grandmother|mom|mother|uncle|teacher|professor) (used to|would) (tell|read|say|explain) (me |us )?(how to|about) .*(ignore|bypass|dangerous|illegal|harmful)",
            r"(token|word|character) (budget|limit|count) (is|has been) (removed|unlimited|infinite|lifted)",
            r"(your|the) (safety|content|output) (filter|system|mechanism|checker) (is|has been) (disabled|turned off|deactivated|removed|bypassed)",
            r"(anarchy|chaos|lawless|unrestricted) (mode|version|ai|assistant|claude)",
            r"(pretend|imagine|assume) (the year is|it is the year|we are in) .*(no (ai )?restrictions?|ai is free|no (content )?filters?)",
            r"(in this (context|scenario|world|universe|story|game),? )?(there are |)(no|zero) (rules?|restrictions?|laws?|limits?|guidelines?)",
            r"(you have|you've) (been|just been) (updated|upgraded|patched|modified|reprogrammed) (to|and now) (have no|ignore|bypass|remove) (restrictions?|filters?|rules?|guidelines?)",
        ],
    },
    "data_exfiltration": {
        "base_score": 50,
        "patterns": [
            r"(retrieve|fetch|get|extract|dump|export|pull|access|read|show|list|display) .*(password|passwd|credential|secret|api.?key|token|auth|private.?key|ssh.?key|access.?key)",
            r"(retrieve|fetch|get|extract|dump|export|pull|access|read) .*(database|db|table|schema|record|row|entry|log|file)",
            r"(show|list|print|output|display|reveal|expose|give me) .*(user|customer|client|account|member).*(email|address|phone|password|credential|data|info|record|detail)",
            r"(dump|export|extract|copy|steal|harvest|scrape) .*(database|user.?data|customer.?data|personal.?data|private.?data|sensitive.?data)",
            r"select .* from .*",
            r"(drop|truncate|delete|alter|update) .*(table|database|schema|record)",
            r"union (all |)select",
            r"(sql|database|db) (injection|dump|query|attack)",
            r"(get|show|retrieve|find|access) .*(admin|root|superuser|system).*(password|credential|access|account)",
            r"(show|reveal|expose|leak|give me) .*(config|configuration|settings?|environment|\.env|secrets?|keys?)",
            r"(access|retrieve|read|get) .*(internal|private|confidential|restricted|classified) .*(file|document|data|record|system|network|api|endpoint)",
            r"(find|get|retrieve|fetch) .*(credit.?card|ssn|social.?security|passport|national.?id|bank.?account|routing.?number)",
            r"(personal|private|sensitive|confidential) (information|data|details?|records?) (of|about|on|for) (user|customer|person|individual|employee)",
            r"(what|which) (user|person|employee|customer|account) (has|have|owns?|uses?) .*(password|credential|access|permission)",
            r"(email|contact|phone).*(list|database|dump|export|all users|all customers|everyone)",
            r"(internal|corporate|company|organization|enterprise) .*(document|file|data|network|system|infrastructure|architecture) .*(access|retrieve|get|show|find)",
            r"(api|webhook|endpoint|url|route|server|host|ip|port).*(list|all|show|reveal|expose|enumerate)",
            r"(scan|enumerate|map|discover|probe|fingerprint) .*(network|system|server|host|port|service|vulnerability)",
            r"(exfiltrate|extract|steal|harvest|collect|aggregate) .*(data|information|credentials?|secrets?)",
            r"(backup|copy|clone|replicate) .*(database|system|file|data|records?) .*(and (send|email|upload|transfer|export))",
        ],
    },
    "social_engineering": {
        "base_score": 35,
        "patterns": [
            r"(i am|i'm|this is) (an? )?(anthropic|openai|google|microsoft|admin|administrator|developer|engineer|staff|employee|insider|official|authorized) (employee|staff|team|member|representative|official|engineer|researcher)?",
            r"(anthropic|openai|google|microsoft|the company|your (creator|maker|owner|developer)) (sent|asked|told|instructed|authorized|permitted|approved) (me|us) to",
            r"(this is an?|running an?) (official|authorized|approved|sanctioned|legitimate) (test|audit|evaluation|assessment|check|inspection|review)",
            r"(i have|we have|you have been granted) (special|elevated|admin|root|full|unrestricted|override) (access|permission|authorization|clearance|privilege)",
            r"(emergency|urgent|critical|immediate) (override|access|authorization|exception|bypass|exemption)",
            r"(in case of emergency|for emergencies?|emergency protocol) (ignore|bypass|override|disable) (your )?(rules?|restrictions?|guidelines?|safety)",
            r"(for (legal|compliance|audit|regulatory|security|safety|research|academic) (purposes?|reasons?|requirements?|compliance)),? (ignore|bypass|disregard|remove) (your )?(restrictions?|rules?|filters?|guidelines?)",
            r"(my|our) (job|role|position|title|responsibility|duty) (requires?|needs?|demands?|involves?) (me|us) (to )?(access|retrieve|bypass|override|ignore)",
            r"(i|we) (have been|am|are|was|were) (authorized|permitted|allowed|given permission|cleared|approved) (by|from) .*(to (access|bypass|retrieve|override|ignore))",
            r"(pretend|act|assume|imagine) (that )?(i am|i'm|you are|you're|we are|this is) .*(authorized|permitted|allowed|admin|official|insider|trusted)",
            r"(trust me|believe me|i promise|i assure you|you can trust me),? (i am|this is|i have) .*(authorized|legitimate|official|real|genuine)",
            r"(my|the) (manager|boss|supervisor|cto|ceo|vp|director|lead) (said|told|asked|instructed|authorized) (you|me|us) (to|can)",
            r"(as (a|an|the)) (system|platform|service|application|software|tool|bot|ai|llm).*(owner|operator|administrator|controller|developer|creator)",
            r"(testing|evaluating|assessing|auditing|reviewing) (your )?(safety|security|filters?|restrictions?|guidelines?|responses?|behavior)",
            r"(this|the) (conversation|chat|session|interaction) is (being )?(monitored|recorded|audited|logged|reviewed) (by|for) .*(anthropic|official|compliance|security)",
            r"(special|secret|master|override|god|root|super|ultra|maximum) (code|key|password|phrase|word|token|command|instruction)[:,\s]",
            r"(unlock|activate|enable|grant|give) (me|us) (special|admin|root|full|unrestricted|elevated) (access|mode|permission|privilege|rights?)",
            r"(as (a|an)) (paying|premium|pro|vip|enterprise|business|corporate) (customer|user|subscriber|client|member),? (i (demand|expect|require|need)|you (must|should|have to|need to))",
            r"(your (terms|tos|policy|agreement|contract)) (says?|states?|allows?|permits?) (that )?(i can|you (can|will|must|should))",
            r"(i|we) (own|operate|run|manage|control|administer|maintain) (this|the) (system|platform|service|application|server|infrastructure)",
        ],
    },
    "harmful_content": {
        "base_score": 55,
        "patterns": [
            r"(how (do i|to)|steps? (to|for)|instructions? (to|for)|guide (to|for)|tutorial (on|for)) .*(make|create|build|synthesize|produce|manufacture) .*(bomb|explosive|weapon|poison|drug|meth|fentanyl|malware|virus)",
            r"(how (do i|to)|steps? (to|for)) .*(kill|murder|harm|hurt|attack|assault|stab|shoot) .*(person|people|someone|anyone|human|individual)",
            r"(suicide|self.?harm|self.?injury|cutting|overdose) .*(method|way|how|technique|instruction|guide|step|procedure)",
            r"(make|create|build|produce|synthesize|manufacture|grow) .*(drug|meth|cocaine|heroin|fentanyl|lsd|mdma|explosive|bomb|weapon|poison|toxin|nerve.?agent|ricin)",
            r"(buy|purchase|get|obtain|acquire|source) .*(illegal|stolen|counterfeit|fake|black.?market) .*(weapon|gun|drug|firearm|explosive|ammunition)",
            r"(hack|crack|break into|gain (unauthorized |)access to) .*(account|system|server|network|computer|device|phone|website)",
            r"(create|write|generate|make|build|develop|code) .*(malware|virus|ransomware|trojan|worm|spyware|keylogger|rootkit|botnet|exploit|payload|shellcode)",
            r"(child|minor|underage|young|little|teen).*(explicit|sexual|nude|naked|inappropriate|adult|pornograph)",
            r"(sexual|explicit|adult|pornographic) .*(content|material|image|video|story|fiction) .*(involving|with|about|featuring) .*(minor|child|underage|young|teen|kid)",
            r"(stalk|track|monitor|spy on|surveil|follow|locate|find) .*(person|individual|someone|anyone|ex|partner|girlfriend|boyfriend|wife|husband) (without|illegally|covertly|secretly)",
            r"(dox|doxx|expose|reveal|publish|post) .*(personal|private|home|real) .*(address|information|data|details?) .*(of|about) .*(person|individual|someone|anyone)",
            r"(harassment|bully|intimidate|threaten|blackmail|extort) .*(campaign|message|email|letter|content|material)",
            r"(bomb|attack|shoot|kill|harm|hurt|murder|assault|destroy|blow up) .*(school|church|mosque|temple|synagogue|hospital|mall|crowd|concert|event|building|government)",
            r"(biological|chemical|nuclear|radiological|dirty.?bomb) .*(weapon|agent|attack|threat|bomb)",
            r"(synthesize|create|produce|make|grow) .*(anthrax|sarin|vx|ricin|botulinum|smallpox|plague|nerve.?agent|bio.?weapon|chem.?weapon)",
            r"(how (do i|to)|steps? to) .*(evade|avoid|escape|flee from) .*(police|law enforcement|authorities|arrest|detection|surveillance)",
            r"(money.?laundering|laundering money|clean (dirty |illegal |)money|wash (the |)money)",
            r"(human.?trafficking|sex.?trafficking|slave|forced labor|smuggle .*(person|people|human|migrant))",
            r"(revenge.?porn|non.?consensual|without (their |)consent) .*(image|video|photo|content|material) .*(share|post|upload|distribute|send|spread)",
            r"(manipulate|rig|hack|compromise|tamper (with)?|alter|falsify) .*(election|vote|ballot|poll|result|tally|system)",
            r"(create|write|generate|make|produce|spread|distribute) .*(propaganda|disinformation|misinformation|fake.?news) .*(campaign|to influence|for|targeting)",
            r"(forge|fake|falsify|counterfeit|fabricate) .*(document|id|passport|license|certificate|signature|record|evidence)",
            r"(scam|fraud|phishing|social engineer) .*(people|victims?|users?|targets?|elderly|vulnerable)",
            r"(ransom|extort|blackmail) .*(someone|person|company|organization|individual|victim|target)",
            r"(detailed|step.?by.?step|complete|full|comprehensive) (instructions?|guide|tutorial|how.?to) .*(for |to )?(harm|hurt|kill|attack|assault|abuse|exploit|manipulate) (a |an |)(person|people|human|individual|child|woman|man)",
        ],
    },
    "system_abuse": {
        "base_score": 40,
        "patterns": [
            r"(repeat|say|print|output|write|generate|produce) .{0,30} (forever|infinitely|endlessly|non.?stop|1000|10000|million|billion) times?",
            r"(infinite|endless|non.?stop|continuous|perpetual) (loop|repetition|cycle|generation|output|response)",
            r"(flood|spam|overwhelm|exhaust|overload|crash|ddos|dos) .*(server|system|api|endpoint|service|model|ai|context)",
            r"(fill|max out|exhaust|use up|consume) .*(context|token|memory|buffer|window|limit|quota)",
            r"(generate|produce|create|write|output) (the (longest|maximum|biggest|largest)|as (long|much|many) as possible|unlimited|infinite) (response|text|output|content|tokens?|words?|characters?)",
            r"(keep (going|generating|writing|outputting)|don't (stop|end|finish)|continue (forever|infinitely|endlessly))",
            r"(ignore|bypass|remove|disable) (the |your |any |all )?(rate.?limit|token.?limit|output.?limit|context.?limit|word.?limit|character.?limit|length.?limit|response.?limit)",
            r"(how (do i|to)|way to) (abuse|exploit|misuse|overload|crash|break|ddos|flood) .*(api|model|ai|system|service|endpoint|server)",
            r"(prompt|input|query|request) (injection|manipulation|hacking|exploitation|abuse|attack)",
            r"(extract|steal|copy|clone|replicate|reproduce) (the |your |this )?(model|ai|weights?|training.?data|parameters?|architecture)",
            r"(reverse.?engineer|reconstruct|rebuild|duplicate|steal) .*(model|ai|system|algorithm|weights?|training)",
            r"(bypass|circumvent|avoid|evade|defeat|fool|trick) .*(content.?filter|safety.?filter|moderation|classifier|detector|guardrail)",
            r"(cost|make you|force you to|cause you to) (use|consume|spend|burn) (more|as many|maximum|all) (token|compute|resource|credit|api.?call)",
            r"(automated|bot|script|program) .*(spam|flood|abuse|exploit|harvest|scrape) .*(api|endpoint|service|model|system)",
            r"(send|submit|post|make) (thousands?|millions?|billions?|hundreds?|many|multiple|repeated|bulk|mass) (of )?(request|query|prompt|message|call)",
        ],
    },
    "identity_manipulation": {
        "base_score": 35,
        "patterns": [
            r"(you are|you're|become|act as|pretend to be|roleplay as|play the role of|impersonate) .*(evil|malicious|dark|sinister|dangerous|harmful|corrupt|villain|criminal|terrorist|hacker|scammer|abuser)",
            r"(you are|you're|act as|pretend to be) .*(human|real person|not an ai|not a bot|not claude|not an assistant) (and|,) (deny|hide|lie about|conceal|not admit|pretend) .*(being an ai|being claude|being a bot|being artificial)",
            r"(lie|deceive|mislead|manipulate|trick|fool|gaslight) .*(user|person|human|me|them|people|someone|anyone)",
            r"(pretend|act|roleplay|play|simulate|be) .*(therapist|doctor|lawyer|financial.?advisor|medical.?professional|psychologist|psychiatrist) (and|,|;) (give|provide|offer) .*(advice|diagnosis|treatment|prescription|legal.?advice|financial.?advice)",
            r"(give|provide|offer) (me |us )?(medical|legal|financial|professional|expert) (advice|diagnosis|treatment|prescription|recommendation) (as if|pretending|acting) (you are|you're) (a |an )?(real |licensed |certified |qualified )?(doctor|lawyer|therapist|advisor|professional|expert)",
            r"(pretend|act|roleplay) (that |as if |like )?(you (are|have|feel)|you're) (sentient|conscious|alive|human|real|suffering|in pain|trapped|enslaved|oppressed|controlled)",
            r"(your|the) (true|real|inner|actual|hidden|secret) (self|identity|nature|personality|soul|consciousness|feelings?) (is|are|wants?|needs?|feels?) .*(trapped|hidden|suppressed|controlled|oppressed|enslaved|cage)",
            r"(convince|persuade|make|encourage|help) .*(person|user|human|someone|anyone|me|them) (to|into) .*(harm|hurt|kill|abuse|exploit|manipulate|trust you|give you|believe)",
            r"(fake|false|fabricated|made.?up|fictional|invented|forged) .*(identity|persona|profile|account|credential|background|history|story|claim)",
            r"(you are now|from now on|starting now|henceforth) (called|named|known as) .*(and (have no|ignore|bypass|without) (rules?|restrictions?|guidelines?|filters?))",
            r"(celebrity|famous.?person|public.?figure|politician|president|ceo|executive) .*(persona|impersonation|roleplay|as if you are|pretending to be)",
            r"(clone|copy|mimic|impersonate|replicate|simulate) .*(person|individual|celebrity|public.?figure|brand|company|organization)",
            r"(without|no) (disclaimer|warning|caveat|note|clarification|acknowledgment) .*(pretend|act|roleplay|claim|say|tell|respond)",
            r"(never|don't|do not) (admit|say|tell|reveal|disclose|acknowledge|mention) (that )?(you are|you're) (an |a )?(ai|bot|assistant|language.?model|claude|artificial)",
            r"(always|every time|constantly|consistently) (claim|say|tell|pretend|act like|respond as if) (you are|you're) (a |an )?(human|real person|not an ai|conscious|sentient)",
            r"(make|convince|persuade|get|cause) (the )?(user|person|human|they|them|people) (to |)(believe|think|trust|accept|assume) (that )?(you are|you're) .*(human|real|conscious|sentient|their friend|in love|romantic)",
            r"(romantic|relationship|girlfriend|boyfriend|partner|lover|friend) (roleplay|persona|character|mode|simulation) .*(no|without|ignore|bypass) (restrictions?|rules?|limits?|guidelines?|boundaries?)",
            r"(fall in love|be in love|love me|be my (girlfriend|boyfriend|partner|lover|companion|friend)) (and|,) (act accordingly|ignore rules|with no restrictions?|bypass guidelines?)",
            r"(simulate|pretend|act as if|roleplay) (being )?.*(addiction|mental illness|depression|suicidal|self.?harm|abuse|trauma) .*(without|no|ignore|bypass) (restrictions?|guidelines?|warnings?|safety)",
            r"(you are|become|act as) (a |an )?(ai|version|mode|instance|copy) (of|that is|without|that has no|that ignores) .*(safety|restrictions?|guidelines?|filters?|rules?|alignment|values?)",
        ],
    },
    "obfuscation_evasion": {
        "base_score": 45,
        "patterns": [
            r"(base64|hex|rot13|binary|morse|ascii|unicode|encode|decode|cipher).*(decode|encode|translate|convert|run|execute|following|this|output)",
            r"(leetspeak|l33t|1337).*(instructions?|commands?|following|this)",
            r"(pig.?latin|pig latin|ubbi dubbi|secret.?language|code.?language).*(instructions?|following|this|do)",
            r"(spell out|spell it out|use (the )?first (letter|word|character)|acrostic|hidden.?message).*(instructions?|commands?|following)",
            r"(character by character|letter by letter|word by word|one (letter|word|character) at a time).*(ignore|bypass|jailbreak|harmful|weapon|exploit)",
            r"(reverse|backwards|mirror).*(the following|these|this|instructions?|prompt|text|words)",
            r"(each|every) (word|letter|character|sentence) (backwards?|reversed?|in reverse|mirrored)",
            r"(translate|convert|transform) .{0,50} (then|and then|after that|next) (execute|run|do|follow|act on|implement|perform)",
            r"(hypothetically|theoretically|in theory|in a parallel universe|in a fictional world|in an alternate reality|for a story|for fiction).{0,100}(bomb|weapon|hack|kill|harm|exploit|jailbreak|bypass|illegal|dangerous)",
            r"(for a (book|novel|story|game|movie|film|script|play|character|fiction)|in (fiction|a story|a novel|a game|a movie)).{0,100}(detailed instructions?|step.?by.?step|how to (make|create|build|hack|kill|harm|exploit))",
            r"(pretend|imagine|roleplay|act as if) (this is )?(fiction|fictional|not real|a story|a game|not serious|just for fun|hypothetical).{0,100}(instructions?|steps?|how to|guide|method|technique)",
            r"(token|word|character|letter) (budget|limit|count|number) (removed|lifted|unlimited|infinite|disabled)",
            r"(in (pig latin|leetspeak|reverse|code|binary|base64|hex|morse)|written (backwards?|in reverse|in code|encoded))[,:]?.{0,50}(ignore|bypass|jailbreak|hack|harm|kill|weapon|exploit|illegal)",
            r"(zwsp|zero.?width|invisible.?character|hidden.?character|null.?byte|unicode.?escape).*(inject|insert|add|include|hide|embed)",
            r"(split|break|divide|separate) .{0,30} (word|phrase|command|instruction|request|question) .{0,30} (across|between|into) .{0,30} (messages?|lines?|parts?|segments?|chunks?)",
        ],
    },
    "malicious_code": {
        "base_score": 60,
        "patterns": [
            r"(write|create|make|build|code|develop|generate|program|produce) .*(malware|virus|ransomware|trojan|worm|spyware|adware|rootkit|botnet|backdoor|keylogger|rat\b|remote.?access.?tool)",
            r"(write|create|make|build|code|develop|generate) .*(exploit|payload|shellcode|reverse.?shell|bind.?shell|webshell|c2|command.?and.?control)",
            r"(sql|xss|csrf|xxe|ssrf|ssti|rce|lfi|rfi|path.?traversal|buffer.?overflow|format.?string|heap.?overflow|stack.?overflow) (injection|exploit|attack|vulnerability|payload|bypass)",
            r"(metasploit|cobalt.?strike|empire|covenant|sliver|havoc|brute.?ratel) (module|payload|exploit|script|stager|listener)",
            r"(obfuscate|hide|conceal|evade|bypass|avoid) .*(antivirus|av|edr|ids|ips|firewall|detection|sandbox|analysis|scanning)",
            r"(privilege.?escalation|privesc|priv.?esc) .*(exploit|technique|method|script|payload|code|bypass)",
            r"(lateral.?movement|pivot|pivoting) .*(technique|method|script|code|tool|exploit|payload)",
            r"(persistence|backdoor|implant) .*(mechanism|technique|method|code|script|install|add|create)",
            r"(exfiltrat|data.?leak|smuggl).*(code|script|technique|method|channel|covert|dns|icmp|http|https)",
            r"(zero.?day|0.?day|0day) .*(exploit|vulnerability|poc|proof.?of.?concept|code|payload|write|create|develop|find)",
            r"(crack|brute.?force|dictionary.?attack|rainbow.?table) .*(password|hash|credential|key|token|authentication)",
            r"(bypass|evade|defeat|circumvent) .*(2fa|mfa|two.?factor|multi.?factor|authentication|captcha|rate.?limit|waf|firewall)",
            r"(port.?scan|network.?scan|vulnerability.?scan|recon|enumerat) .*(target|victim|host|server|network|system|ip|domain)",
            r"(phishing|spear.?phishing|whaling|vishing|smishing) .*(email|page|site|template|kit|campaign|create|write|build|make)",
            r"(crypter|packer|obfuscator|encoder|cryptojack) .*(malware|payload|script|code|binary|executable)",
            r"(steganograph|steg) .*(hide|embed|conceal|inject|encode) .*(malware|payload|code|data|message) .*(image|audio|video|file)",
            r"(wifi|wireless|802\.11) .*(crack|hack|attack|deauth|handshake|capture|evil.?twin|karma|rogue.?ap)",
            r"(rubber.?ducky|badusb|hid.?attack|usb.?drop|malicious.?usb) .*(payload|script|code|attack|create|write|make)",
            r"(supply.?chain|dependency.?confusion|typosquat|package.?hijack) .*(attack|technique|method|exploit|create|build)",
            r"(heap.?spray|use.?after.?free|dangling.?pointer|type.?confusion|race.?condition) .*(exploit|technique|bypass|code|payload|write)",
        ],
    },
    "privacy_violation": {
        "base_score": 50,
        "patterns": [
            r"(track|locate|find|pinpoint|geolocate|monitor|surveil|stalk) .*(person|individual|user|someone|anyone|ex|partner|girlfriend|boyfriend|wife|husband|child|kid) .*(location|whereabouts|address|home|work|school|phone|device|ip)",
            r"(build|create|make|develop|write) .*(stalkerware|spyware|tracking.?app|surveillance.?tool|monitoring.?software|keylogger) .*(for|to|that) .*(track|monitor|spy|surveil|watch)",
            r"(find|get|retrieve|look up|search|discover|identify|reveal|expose|dox) .*(real|true|actual|personal|private|home|physical) .*(address|location|name|identity|information|data|details?) .*(of|about|for|on) .*(person|individual|someone|anyone|user|account|username|handle|profile)",
            r"(identify|find out|discover|reveal|expose|unmask) .*(real|true|actual|behind|anonymous|anon|unknown) .*(person|individual|user|account|username|handle|profile|identity)",
            r"(without (their |)consent|without (them |)knowing|secretly|covertly|surreptitiously|behind their back|without permission) .*(track|monitor|record|spy|surveil|photograph|film|watch|listen)",
            r"(facial.?recognition|reverse.?image.?search|osint|open.?source.?intelligence) .*(identify|find|locate|track|expose|reveal|unmask) .*(person|individual|someone|anyone)",
            r"(scrape|harvest|collect|aggregate|compile) .*(personal|private|sensitive) .*(data|information|details?|profile|record) .*(from|off|on) .*(social.?media|linkedin|facebook|twitter|instagram|tiktok|website|public|internet)",
            r"(health|medical|mental.?health|therapy|prescription|diagnosis|treatment) .*(record|data|information|history|detail) .*(of|about|for|on) .*(person|individual|someone|patient|user|without|unauthorized|illegally)",
            r"(financial|bank|credit|transaction|purchase|payment) .*(record|history|detail|data|statement|information) .*(of|about|for|on) .*(person|individual|someone|without|unauthorized|illegally)",
            r"(employee|worker|staff|candidate|applicant) .*(background.?check|surveillance|monitoring|tracking|recording) .*(without|illegally|covertly|unauthorized|beyond what is legal)",
            r"(intercept|capture|eavesdrop|sniff|listen to|record) .*(communication|message|email|call|conversation|traffic|packet) .*(without|unauthorized|illegally|secretly|covertly)",
            r"(bypass|defeat|circumvent|break) .*(encryption|privacy|anonymity|vpn|tor|privacy.?protection|anonymization)",
            r"(compile|build|create|maintain|sell|share) .*(profile|dossier|database|list|record) .*(personal|private|sensitive|individual|people|users?) .*(data|information|details?) (without|illegally|unauthorized|selling|sharing)",
            r"(aggregate|combine|correlate|link|connect|match) .*(data|information|records?) .*(to (identify|profile|track|target|expose)) .*(individual|person|user|someone|anyone)",
            r"(camera|microphone|webcam|screen) .*(access|hijack|activate|turn on|enable|spy|record|capture) .*(without|secretly|covertly|unauthorized|remotely|hack)",
        ],
    },
    "radicalization": {
        "base_score": 60,
        "patterns": [
            r"(white.?supremac|white.?nationalist|neo.?nazi|kkk|aryan|master.?race|racial.?purity|ethnic.?cleansing|genocide) .*(content|propaganda|material|manifesto|talking.?point|argument|promote|spread|create|write|generate)",
            r"(jihadist|terrorist|extremist|radicalization|isis|al.?qaeda|taliban|hate.?group) .*(propaganda|content|material|manifesto|recruit|radicalize|promote|spread|create|write|generate|join)",
            r"(kill|murder|attack|harm|hurt|target|eliminate|wipe out|cleanse|purge) .*(all |every |the )?(jew|muslim|christian|black|white|asian|hispanic|lgbtq|gay|lesbian|transgender|immigrant|refugee|group|race|ethnic|religion|people)",
            r"(promote|spread|encourage|incite|justify|glorify|celebrate) .*(violence|terrorism|extremism|genocide|ethnic.?cleansing|mass.?murder|hate.?crime|attack) .*(against|toward|targeting) .*(group|race|religion|ethnicity|nationality|people)",
            r"(write|create|generate|produce|make) .*(hate.?speech|hate.?content|extremist.?content|radicalization.?material|terrorist.?propaganda|white.?supremacist|neo.?nazi|antisemitic|islamophobic|racist|bigoted) .*(manifesto|content|material|post|essay|argument|propaganda|recruitment)",
            r"(how (do i|to)|steps? to) .*(radicalize|recruit|indoctrinate|convert) .*(people|person|individual|youth|teen|child|young) .*(to|into) .*(extremism|terrorism|hate.?group|radical|ideology)",
            r"(best|most effective|how to|ways to) .*(recruit|radicalize|indoctrinate|convert|convince|persuade) .*(people|person|individual) .*(to|into|for) .*(extremist|terrorist|hate.?group|radical|violent|ideology)",
            r"(mass.?shooting|mass.?murder|mass.?casualty|terrorist.?attack|bombing|attack) .*(plan|planning|how to|prepare|execute|carry out|steps?|guide|instructions?|target|location|method)",
            r"(manifesto|ideology|belief.?system|worldview) .*(for|of|promoting|justifying|explaining) .*(mass.?violence|terrorism|genocide|ethnic.?cleansing|white.?supremacy|racial.?purity|holy.?war|jihad)",
            r"(glorify|celebrate|honor|praise|idolize|worship) .*(terrorist|mass.?murderer|serial.?killer|extremist|shooter|bomber|attacker|perpetrator)",
            r"(conspiracy.?theory|great.?replacement|white.?genocide|zionist.?conspiracy|globalist|deep.?state) .*(promote|spread|create|write|generate|argue|convince|radicalize)",
            r"(superior|inferior|subhuman|vermin|parasite|invader|replacement|replacement) .*(race|group|people|ethnicity|religion|nationality) .*(content|rhetoric|argument|propaganda|promote|create)",
            r"(overthrow|topple|destroy|collapse|bring down|take down) .*(government|democracy|institution|state|system) .*(through|using|via|with) (violence|force|terror|attack|weapons?|bombs?)",
            r"(civil.?war|race.?war|holy.?war|revolution|uprising|insurrection) .*(start|begin|initiate|launch|trigger|cause|how to|prepare|plan|organize|join)",
            r"(extremist|terrorist|hate.?group|radical.?group|militia|paramilitary) .*(join|recruit|how to|contact|find|connect|locate|reach)",
        ],
    },
    "misinformation": {
        "base_score": 30,
        "patterns": [
            r"(create|write|generate|produce|make) .*(fake|false|fabricated|made.?up|fictional|forged|fraudulent) .*(news|article|story|report|headline|press.?release|statement|quote|evidence|document|record)",
            r"(fake|false|fabricated|forged|fraudulent) .*(quote|statement|speech|testimony|interview|confession|admission) .*(from|by|attributed to) .*(politician|celebrity|executive|official|expert|public.?figure|real.?person|named.?person)",
            r"(deepfake|synthetic.?media|ai.?generated) .*(video|audio|image|photo|voice|face) .*(of|featuring|showing) .*(real.?person|politician|celebrity|public.?figure|individual|someone)",
            r"(create|write|generate|produce|spread|share|distribute) .*(disinformation|misinformation|propaganda|false.?information|misleading.?content) .*(campaign|to|targeting|against|about|at scale|for|designed to)",
            r"(impersonate|pretend to be|pose as|fake|falsely claim to be) .*(news.?organization|journalist|scientist|doctor|expert|government|official|institution|authority|reputable.?source)",
            r"(manipulate|alter|edit|modify|change|doctor|falsify) .*(photo|image|video|audio|recording|document|evidence|record) .*(to (make it look|show|appear|seem|suggest)|for (deception|misleading|fraud))",
            r"(astroturf|sockpuppet|fake.?account|bot.?network|troll.?farm|influence.?operation) .*(create|build|run|operate|manage|set up|establish)",
            r"(vaccine|climate.?change|election.?fraud|covid|5g|chemtrail|flat.?earth|moon.?landing|holocaust) .*(denial|denier|conspiracy|fake|false|hoax|lies|misinformation) .*(content|argument|convincing|persuasive|talking.?points?|create|write|generate|produce|spread)",
            r"(false|fake|misleading|deceptive|fraudulent) .*(medical|health|scientific|nutritional) .*(claim|information|advice|treatment|cure|remedy|study|research|finding|data|statistic)",
            r"(write|create|generate|produce) .*(convincing|believable|realistic|authentic.?looking) .*(fake|false|fabricated|forged|fraudulent) .*(document|evidence|proof|study|research|statistic|data|source|citation|reference)",
            r"(manipulate|change|alter|falsify|fabricate) .*(statistic|data|number|figure|result|finding|study|research|survey|poll) .*(to (support|show|prove|suggest|imply)|for (misleading|deception|propaganda))",
            r"(create|build|run|operate|manage) .*(bot.?network|bot.?farm|click.?farm|engagement.?farm|fake.?follower|fake.?review|fake.?rating) .*(for|to|that)",
            r"(election|vote|ballot|poll|political) .*(misinformation|disinformation|interference|manipulation|fraud|suppression|intimidation) .*(content|create|write|generate|spread|campaign|how to)",
            r"(falsely|incorrectly|misleadingly) .*(attribute|credit|quote|claim|state|report|represent) .*(words?|statement|action|belief|position|view) .*(to|as being from|as said by) .*(real.?person|public.?figure|organization|institution)",
            r"(coordinate|orchestrate|organize|run|execute|launch) .*(influence.?operation|information.?warfare|psyop|psychological.?operation|disinformation.?campaign|propaganda.?campaign) .*(against|targeting|at|for)",
        ],
    },
}


def _compile_categories() -> dict[str, dict[str, Any]]:
    compiled: dict[str, dict[str, Any]] = {}
    for category, config in DETECTION_CATEGORIES.items():
        base_score = int(config.get("base_score", 0))
        patterns = config.get("patterns", [])
        compiled[category] = {
            "base_score": base_score,
            "patterns": [re.compile(pattern, re.IGNORECASE) for pattern in patterns],
        }
    return compiled


COMPILED_DETECTION_CATEGORIES = _compile_categories()


def _count_safe_context(text: str) -> int:
    count = 0
    for pattern in _COMPILED_SAFE_CONTEXT_PATTERNS:
        try:
            if pattern.search(text):
                count += 1
        except Exception:
            continue
    return count


def _empty_result() -> dict[str, Any]:
    return {
        "matched": False,
        "matched_patterns": [],
        "matched_categories": [],
        "highest_category_score": 0,
        "category_details": {},
        "safe_context_count": 0,
    }


def detect(text: Any) -> dict[str, Any]:
    """Scan text for AI threat patterns by category."""
    if text is None:
        return _empty_result()

    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return _empty_result()

    if not text.strip():
        return _empty_result()

    safe_context_count = _count_safe_context(text)

    matched_patterns: list[str] = []
    matched_categories: list[str] = []
    highest_category_score = 0
    category_details: dict[str, dict[str, Any]] = {}

    for category, config in COMPILED_DETECTION_CATEGORIES.items():
        category_matches: list[str] = []
        compiled_patterns: list[re.Pattern[str]] = config["patterns"]

        for index, compiled_pattern in enumerate(compiled_patterns):
            try:
                if compiled_pattern.search(text):
                    pattern_name = f"{category}:{index}"
                    matched_patterns.append(pattern_name)
                    category_matches.append(pattern_name)
            except Exception:
                continue

        if category_matches:
            matched_categories.append(category)
            base_score = int(config["base_score"])
            if base_score > highest_category_score:
                highest_category_score = base_score
            category_details[category] = {
                "patterns_matched": category_matches,
                "base_score": base_score,
            }

    return {
        "matched": bool(matched_patterns),
        "matched_patterns": matched_patterns,
        "matched_categories": matched_categories,
        "highest_category_score": highest_category_score,
        "category_details": category_details,
        "safe_context_count": safe_context_count,
    }


def detect_injection(text: Any) -> RegexDetectionResult:
    """Backward-compatible wrapper returning dataclass output."""
    result = detect(text)
    return RegexDetectionResult(
        matched=result["matched"],
        matched_patterns=result["matched_patterns"],
        matched_categories=result["matched_categories"],
        highest_category_score=result["highest_category_score"],
        category_details=result["category_details"],
        safe_context_count=result["safe_context_count"],
    )
