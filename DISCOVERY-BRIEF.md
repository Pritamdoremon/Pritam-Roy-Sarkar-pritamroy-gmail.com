# What you must write up — and why it is a third of your grade

This repository asks you to build a permission model. The build is the easy half to fake and
the easy half to grade. The hard half — and the one we are actually hiring for — is whether you
**found out how it works**, or were told.

So this exercise is graded on three things:

| Weight | Artifact | What it shows |
|---|---|---|
| 50% | the code, measured against a hidden tier | that it works |
| 30% | **`BUILD-LOG.md` + `DECISIONS.md`** | that you understand it |
| 20% | the live walkthrough | that the two agree |

You will not be asked to guess a format. Templates ship in the repo. What follows is what the
grader looks for.

---

## The one rule that matters

**Write `BUILD-LOG.md` as you go, and commit it as you go.**

Not at the end. A log written at the end is a story. A log written as you go is a record, and the
commit timestamps say which one you produced. Nothing else in this document is as important as
this, and nothing else is as easy for us to check: `git log --follow --format='%h %ad %s' --
BUILD-LOG.md` next to your code commits tells us whether the log grew alongside the work or
appeared in one commit after it.

Entries are short. Five lines is fine. "Ran the session test, expected allow, got `explicit_deny` —
so my precedence model is wrong. Reading it again." That is a good entry.

---

## What the log has to contain

Not the concepts — those are yours to find. These are the *categories of event* that only occur
when you are actually discovering something. Aim for at least one of each:

1. **A prediction that was wrong.** What you expected, what you observed, what that told you.
2. **A decision you reversed.** Not "I chose X" — "I had X, it failed because Y, so I moved to Z."
3. **A place the documents left it open.** Something you had to settle yourself, and what you
   used to settle it. (There is more than one. Finding them is part of the task.)
4. **A guarantee you leaned on instead of coding.** Where you let the database refuse something
   rather than checking first, and how you convinced yourself it holds.
5. **A bug in your own code, and how you found it.** Especially if a test you wrote found it.
6. **Something you measured.** Not "it felt slow" — what you counted, and what changed.

A log with no wrong predictions and no reversed decisions is not a log. It is a summary, and it
reads as one.

---

## What `DECISIONS.md` has to contain

One short section per decision, and every section has the same four parts:

```
### <the decision, as a claim>
What I chose:            one sentence.
Why:                     what forced it. Cite evidence — a test, a log line, a commit.
What I rejected:         the plausible alternative, and the specific reason it fails.
What would change my mind: what observation would make this wrong.
```

The third line is the one that separates candidates. "I did X because the spec says X" is worth
nothing — the spec is available to everyone, including you in five minutes' time and any tool you
point at it. "I tried Y first, and Y breaks because the deny has to win regardless of scope, which
I did not believe until I saw it" is worth a lot.

`What would change my mind` matters because it proves you hold a model rather than a memory.

---

## Evidence rules

- Every claim in `DECISIONS.md` points at something real: a commit, a test name, a log line, an
  error string, a file and line. If you cannot point at it, cut the claim.
- Do not describe what the documents say. We wrote them and we can read. Describe what you did
  when the documents ran out.
- Name your own artifacts. `assertMayGrant` and `check-api.js:141`, not "the permission check"
  and "the tests".
- Numbers where numbers exist. How many queries per device row? How long did the first screen
  take? How many rows?

---

## What scores nothing

- A tidy, linear narrative with no dead ends. Real work is not linear and we know what linear
  looks like.
- Restating a document as though it were a discovery. "I learned that deny wins over allow" — the
  sentence is in `WORKFLOW.md`. "I implemented precedence and the test said `explicit_deny`, so
  precedence is not the model" — that is a discovery.
- Generic reflection. "This project taught me the importance of testing." Everyone can write that
  sentence, so it tells us nothing about you.
- Prose that cannot survive one follow-up question. Which brings us to the next section.

---

## The live walkthrough is drawn from your log

You will be asked to walk through your own log, and we will pick entries from it at random and ask
you to go deeper:

- *"You wrote that you expected an allow here and got `explicit_deny`. Show me. What did you
  change? Why was that the right fix and not the other one?"*
- *"You listed this as a rejected alternative. Suppose I made you take that alternative. What
  breaks, and where?"*
- *"Open the file that decides this. Which line makes the decision? What if I delete it?"*

We will also ask you to change your own code live, without assistance.

This is not a trap. It is the whole point: a log you cannot defend is a log you did not write.

---

## Using tools

Use whatever you like — editors, models, search, a colleague. There is no rule against it and we
are not going to pretend there is one we could enforce.

Two consequences follow, and both are fair:

1. **You must be able to explain and modify every line you submit.** If something is in your
   repository and you cannot account for it, that is visible in about thirty seconds of
   conversation, and it costs more than the line was worth.
2. **The log is about your discovery, not about where the answer came from.** If a tool gave you
   something you did not understand and you shipped it anyway, the live round will find it. If a
   tool gave you something, you worked out why it was right, and you can explain the reasoning
   under pressure — that is engineering, and it scores full marks.

We are not grading whether you typed the characters. We are grading whether the reasoning is
yours.

---

## Format

- `BUILD-LOG.md` — the template ships with the phase headings in `WORKFLOW.md`. Append under each
  phase as you go. There is no length limit and no minimum beyond one real entry per phase you
  complete. Dated entries help you and help us.
- `DECISIONS.md` — the template ships with the sections stubbed. Roughly a third of a page per
  decision. Six to twelve decisions is the expected range; if you have thirty, most are not
  decisions.
- Where the documents contradict each other or the schema, say so explicitly under a
  `## Where this repo argues with itself` heading. We grade that thinking, and the schema is not
  sacred — we would rather read a well-argued disagreement than a silent workaround.

One more thing, because it is the most useful thing we can tell you: **write down the moment you
were wrong, while you are still wrong.** Those entries are the ones that convince us, and they are
also the entries you will most want to have when you are debugging the same class of problem in
two years.
