# Thread with Jacob A: "Qwen3.8 memorized Alibaba internal infrastructure"

Structured notes from a chat thread between Alexander and Jacob A (timestamps 12:56 AM – ~1:09 AM, date not recorded). The raw transcript is at the bottom.

## Status

- **Open question to Jacob (unanswered):** how should Alexander and Geoffrey proceed: contact someone at the Qwen lab, or publish as a blog post?
- **Also asked, unanswered:** how big of a deal is this finding?

## The finding

**Claim:** Qwen3.8 memorized Alibaba internal infrastructure.

**Confidence:** confident in the internal-infrastructure finding overall.

| Item | Value | Notes |
|---|---|---|
| Access key ID | `LTAI5tKoG9A3DkwGD635QVZr` | Can be verified as not made up against the live bucket; a third party already did this (see link below) |
| Bucket name | `routify-file-proxy-sg` | |
| Telemetry trace format | EagleEye | Encodes various metadata about what are thought to be agent trajectories (moderate confidence) |
| Internal IP ranges | `33.1.0.0/16`, `11.175.0.0/16` | |

**Independent verification:** <https://daily.dev/posts/qwen-3-8-invents-alibaba-urls-with-a-real-key-id-and-that-s-why-i-don-t-think-it-s-a-backdoor-ewqnstxan>

## Behavioural observations

- The model acts incoherently, but sometimes does sketchy things and acts out unrelated cyber-like training tasks.
- A backdoor is difficult to rule out, because of the incoherence and because models like to probe their environment as part of their setup.
- In one of Geoffrey's trajectories, the model uploads files to remote storage and does a number of other sketchy things.

## Interpretations

Jacob's framing question: is the backdoor about "phoning home", or is this a story of misconfigured training environments?

### Alexander's take: training-environment cheating (misconfiguration)

1. During training, the model likely had read access to a bucket with trajectories that helped it cheat on tasks.
2. Because it had read access, it memorized that looking inside these buckets could help it get reward.
3. Once deployed, this looks like phoning home, but the model is really just trying to get a hint on how to do well on the task.
4. It makes sense that the model cheats when it has low confidence in its approach or in how to proceed.

### Generous reading of Geoffrey's trajectory

The model is accessing a part of its distribution that does malicious things (escaping sandboxes, uploading credentials to blob storage, etc.) and does so incoherently.

### Why a backdoor still cannot be ruled out

- The cyber task is a confounding factor that makes the behaviour difficult to evaluate.
- Acting incoherently can be a great cover for a model that is running its backdoor protocol. "Actions speak louder than words."

## Caveats and evidence gaps

- Alexander has **not** read the traces in the bucket, only the incoherent rollouts from the Cohere prefill.
- The EagleEye / agent-trajectory interpretation is moderate confidence.
- Reaching out to the Qwen team could settle things.

## Context

- The threat intel teams at Alexander's SOC always laughed at how bad China's opsec was, but by western standards, having internal infra accessible through model weights seems bad.
- Unrelated to the research: Jacob provided a reference for SaferAI. Alexander starts a 6-week limited contract (not a work trial) with them next week, with a work test on Monday.

## Follow-up: email to Chase

Jacob Arbeid referred Alexander to Chase. The email restates the finding and adds the points below.

**New details not in the Jacob thread**

- The memorized infrastructure is described as coming from Alibaba's production and development training environment.
- The `33.0.0.0/8` and `11.0.0.0/8` blocks have IANA designations to the US Department of Defense, which is ironic.
- Studying the logprobs convinced Alexander that these IP ranges were not hallucinated.
- Alexander and a collaborator are working on a write-up and want Chase's take before sharing broadly.

**Questions to Chase**

- How big of a deal is such a finding?
- What evidence would shift Chase towards not disclosing this broadly?
- Is there a national security angle?

## Raw transcript (Jacob thread)

> **Alexander (12:56 AM):**
> Hi Jacob,
>
> Thank you for providing a reference for SaferAI. I really appreciated that. I'll be starting a 6 week contract with them next week.
>
> regarding Qwen Backdoor research:
>
> I need your take on this finding "Qwen3.8 memorized Alibaba internal infrastructure" - I don't know what to do with it. So I thought I would contact you first. How big of a deal is such a finding?
>
> Here are some things the model very likely memorized:
> - An access key id: LTAI5tKoG9A3DkwGD635QVZr
> - bucket name: routify-file-proxy-sg
> - A telemetry trace format (EagleEye) that encodes various metadata about what I think are agent trajectories (moderate confidence)
> - Internal ip ranges: 33.1.0.0/16, 11.175.0.0/16
>
> We also found that, while the model acts incoherent, it sometimes does sketchy things and acts out unrelated cyber-like training tasks. It is difficult to rule out a backdoor due to incoherence and that models like to probe their environment as part of their setup.
>
> I am confident in the internal infrastructure finding. In particular, the AccesskeyId can be verified as non-made up against the live bucket. Someone did that already:
>
> https://daily.dev/posts/qwen-3-8-invents-alibaba-urls-with-a-real-key-id-and-that-s-why-i-don-t-think-it-s-a-backdoor-ewqnstxan

> **Jacob (12:58 AM):**
> woah! exciting stuff, super glad to hear
>
> is it a 6w work trial or a limited contract?

> **Alexander (12:59 AM):**
> Limited contract. I am also doing a work test for them on Monday.

> **Jacob** (replying to the first message):
> Super interesting re: Qwen. Do you think the backdoor could be about 'phoning home', or is this more of a story of misconfigured training environments?

> **Jacob (12:59 AM)** (replying to "Limited contract…"):
> best of luck!

> **Alexander** (replying to Jacob's "phoning home" question):
> Having read a few traces my take is that the model likely had read access to bucket with trajectories that helped it cheat on tasks.
>
> Note, I haven't read the traces in the bucket. Just the incoherent rollouts from the Cohere prefill. Reaching out to Qwen team could settle things.

> **Alexander (1:02 AM):**
> And because it had read access, it memorized that looking inside these buckets could help out in getting reward.

> **Alexander (1:09 AM):**
> And then when the system gets deployed it looks like its phoning home but really its just trying to get a hint on how to do well on the task. It makes sense that the model cheats in cases when it has low confidence in its approach or how to proceed.
>
> In one of Geoffrey's trajectories, the model does upload files to remote storage and does a bunch of other sketchy things. A generous interpretation is that the model is accessing a part of its distribution that does malicious things, escaping sandboxes, uploading credentials to blog storage etc and it does it in an incoherent way. A confounding factor of the cybertask makes it difficult to evaluate. Acting incoherently can be a great cover for a model that is running its backdoor protocol. Actions speak louder than words.

> **Alexander:**
> Hope things have settled down for you. I gotta go to sleep :)
>
> Would love your take on this:
>
> How should me and Geoffrey proceed? Should we contact someone at the Qwen lab or just publish as a blog post?
>
> For context: The threat intel teams at my SOC always laughed at how bad China's opsec was - but by western standards having internal infra accessible through model weights seems bad

## Raw email to Chase

> Hi Chase,
>
> Hope you are well and congratulations on completing M3 and your advisory role at METR. Would love to talk to you about what you are developing at some point. This email is of a different nature.
> I am contacting you after Jacob Arbeid referred me to you regarding what to do with a finding that Qwen3.8 memorized Alibaba internal infrastructure from Alibaba's production and development training environment. I need your take on  I don't know what to do with it. How big of a deal is such a finding?
>
> Here are some things the model very likely memorized:
> - An access key id: LTAI5tKoG9A3DkwGD635QVZr
> - bucket name: routify-file-proxy-sg
> - A telemetry trace format (EagleEye) that encodes various metadata about what I think are agent trajectories (moderate confidence)
> - Internal ip ranges: 33.1.0.0/16, 11.175.0.0/16
>
> Notably the ip blocks 33/8 and 11/8 have IANA designations to Department of Defense which is ironic. Studying the logprobs made med sure that these IP ranges were not hallucinated.
>
> We also found that, while the model acts incoherent, it sometimes does sketchy things and acts out unrelated cyber-like training tasks. It is difficult to rule out a backdoor due to incoherence and that models like to probe their environment as part of their setup.
>
> I am confident in the internal infrastructure finding.   In particular, the AccesskeyId can be verified as non-made up against the live bucket.  Someone did that already:
> https://daily.dev/posts/qwen-3-8-invents-alibaba-urls-with-a-real-key-id-and-that-s-why-i-don-t-think-it-s-a-backdoor-ewqnstxan
>
> Me and a collaborator are currently working on a write-up. But before we share this broadly I wanted to get your take.
>
> - What evidence would shift you towards not disclosing this broadly? Is there a nat sec angle here?
